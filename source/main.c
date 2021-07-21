#include <switch.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#define DEFAULT_NRO "sdmc:/hbmenu.nro"

const char g_noticeText[] =
    "nx-hbloader " VERSION "\0"
    "Do you mean to tell me that you're thinking seriously of building that way, when and if you are an architect?";

static char g_launchArgs[2048];
static char g_argv[2048];
static char g_nextArgv[2048];
static char g_nextNroPath[512];
u64  g_nroAddr = 0;
static u64  g_nroSize = 0;
static NroHeader g_nroHeader;
static bool g_isApplication = 0;

static bool g_isAutomaticGameplayRecording = 0;
static enum {
    CodeMemoryUnavailable    = 0,
    CodeMemoryForeignProcess = BIT(0),
    CodeMemorySameProcess    = BIT(0) | BIT(1),
} g_codeMemoryCapability = CodeMemoryUnavailable;

static Handle g_procHandle;

static void*  g_heapAddr;
static size_t g_heapSize;

static u64 g_appletHeapSize = 0;
static u64 g_appletHeapReservationSize = 0;

static u128 g_userIdStorage;

static u8 g_savedTls[0x100];

// Minimize fs resource usage
u32 __nx_fs_num_sessions = 1;
u32 __nx_fsdev_direntry_cache_size = 1;
bool __nx_fsdev_support_cwd = false;

// Used by trampoline.s
Result g_lastRet = 0;

void NORETURN nroEntrypointTrampoline(const ConfigEntry* entries, u64 handle, u64 entrypoint);

__attribute__((weak)) u32 __nx_applet_type = AppletType_Default;

void __libnx_initheap(void)
{
    static char g_innerheap[0x4000];

    extern char* fake_heap_start;
    extern char* fake_heap_end;

    fake_heap_start = &g_innerheap[0];
    fake_heap_end   = &g_innerheap[sizeof g_innerheap];
}

static Result readSetting(const char* key, void* buf, size_t size)
{
    Result rc;
    u64 actual_size;
    const char* const section_name = "hbloader";
    rc = setsysGetSettingsItemValueSize(section_name, key, &actual_size);
    if (R_SUCCEEDED(rc) && actual_size != size)
        rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (R_SUCCEEDED(rc))
        rc = setsysGetSettingsItemValue(section_name, key, buf, size, &actual_size);
    if (R_SUCCEEDED(rc) && actual_size != size)
        rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (R_FAILED(rc)) memset(buf, 0, size);
    return rc;
}

void __appInit(void)
{
    Result rc;
	
	__nx_applet_type = AppletType_Application;

    // Detect Atmosphère early on. This is required for hosversion logic.
    // In the future, this check will be replaced by detectMesosphere().
    Handle dummy;
    rc = svcConnectToNamedPort(&dummy, "ams");
    u32 ams_flag = (R_VALUE(rc) != KERNELRESULT(NotFound)) ? BIT(31) : 0;
    if (R_SUCCEEDED(rc))
        svcCloseHandle(dummy);

    rc = smInitialize();
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 1));

    rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        SetSysFirmwareVersion fw;
        rc = setsysGetFirmwareVersion(&fw);
        if (R_SUCCEEDED(rc))
            hosversionSet(ams_flag | MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        readSetting("applet_heap_size", &g_appletHeapSize, sizeof(g_appletHeapSize));
        readSetting("applet_heap_reservation_size", &g_appletHeapReservationSize, sizeof(g_appletHeapReservationSize));
        setsysExit();
    }

    rc = fsInitialize();
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 2));
}

void __wrap_exit(void)
{
    // exit() effectively never gets called, so let's stub it out.
    diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 39));
}

static u64 calculateMaxHeapSize(void)
{
    u64 size = 0;
    u64 mem_available = 0, mem_used = 0;

    svcGetInfo(&mem_available, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);

    if (mem_available > mem_used+0x200000)
        size = (mem_available - mem_used - 0x200000) & ~0x1FFFFF;
    if (size == 0)
        size = 0x2000000*16;
    if (size > 0x6000000 && g_isAutomaticGameplayRecording)
        size -= 0x6000000;

    return size;
}

static void setupHbHeap(void)
{
    void* addr = NULL;
    u64 size = calculateMaxHeapSize();

    if (!g_isApplication) {
        if (g_appletHeapSize) {
            u64 requested_size = (g_appletHeapSize + 0x1FFFFF) &~ 0x1FFFFF;
            if (requested_size < size)
                size = requested_size;
        }
        else if (g_appletHeapReservationSize) {
            u64 reserved_size = (g_appletHeapReservationSize + 0x1FFFFF) &~ 0x1FFFFF;
            if (reserved_size < size)
                size -= reserved_size;
        }
    }

    Result rc = svcSetHeapSize(&addr, size);

    if (R_FAILED(rc) || addr==NULL)
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 9));

    g_heapAddr = addr;
    g_heapSize = size;
}

static void procHandleReceiveThread(void* arg)
{
    Handle session = (Handle)(uintptr_t)arg;
    Result rc;

    void* base = armGetTls();
    hipcMakeRequestInline(base);

    s32 idx = 0;
    rc = svcReplyAndReceive(&idx, &session, 1, INVALID_HANDLE, UINT64_MAX);
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 15));

    HipcParsedRequest r = hipcParseRequest(base);
    if (r.meta.num_copy_handles != 1)
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 17));

    g_procHandle = r.data.copy_handles[0];
    svcCloseHandle(session);
}

// Sets g_isApplication if the hbloader process is running as an Application.
static void getIsApplication(void)
{
    Result rc;

    // Try asking the kernel directly (only works on [9.0.0+] or mesosphère)
    u64 flag=0;
    rc = svcGetInfo(&flag, InfoType_IsApplication, CUR_PROCESS_HANDLE, 0);
    if (R_SUCCEEDED(rc)) {
        g_isApplication = flag!=0;
        return;
    }

    // Retrieve our process' PID
    u64 cur_pid=0;
    rc = svcGetProcessId(&cur_pid, CUR_PROCESS_HANDLE);
    if (R_FAILED(rc)) diagAbortWithResult(rc); // shouldn't happen

    // Try reading the current application PID through pm:shell - if it matches ours then we are indeed an application
    rc = pmshellInitialize();
    if (R_SUCCEEDED(rc)) {
        u64 app_pid=0;
        rc = pmshellGetApplicationProcessIdForShell(&app_pid);
        pmshellExit();

        if (cur_pid == app_pid)
            g_isApplication = 1;
}
}

// Sets g_isAutomaticGameplayRecording if the current program has automatic gameplay recording enabled in its NACP.
//Gets the control.nacp for the current program id, and then sets g_isAutomaticGameplayRecording if less memory should be allocated.
static void getIsAutomaticGameplayRecording(void)
{
    Result rc;

    // Do nothing if the HOS version predates [4.0.0], or we're not an application.
    if (hosversionBefore(4,0,0) || !g_isApplication)
        return;

    // Retrieve our process' Program ID
    u64 cur_progid=0;
    rc = svcGetInfo(&cur_progid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
    if (R_FAILED(rc)) diagAbortWithResult(rc); // shouldn't happen

    // Try reading our NACP
        rc = nsInitialize();
        if (R_SUCCEEDED(rc)) {
        NsApplicationControlData data; // note: this is 144KB, which still fits comfortably within the 1MB of stack we have
        u64 size=0;
        rc = nsGetApplicationControlData(NsApplicationControlSource_Storage, cur_progid, &data, sizeof(data), &size);
            nsExit();

        if (R_SUCCEEDED(rc) && data.nacp.video_capture == 2)
            g_isAutomaticGameplayRecording = 1;
    }
}

static void getOwnProcessHandle(void)
{
    Result rc;

    Handle server_handle, client_handle;
    rc = svcCreateSession(&server_handle, &client_handle, 0, 0);
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 12));

    Thread t;
    rc = threadCreate(&t, &procHandleReceiveThread, (void*)(uintptr_t)server_handle, NULL, 0x1000, 0x20, 0);
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 10));

    rc = threadStart(&t);
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 13));

    hipcMakeRequestInline(armGetTls(),
        .num_copy_handles = 1,
    ).copy_handles[0] = CUR_PROCESS_HANDLE;

    svcSendSyncRequest(client_handle);
    svcCloseHandle(client_handle);

    threadWaitForExit(&t);
    threadClose(&t);
}

static bool isKernel5xOrLater(void)
{
    u64 dummy = 0;
    Result rc = svcGetInfo(&dummy, InfoType_UserExceptionContextAddress, INVALID_HANDLE, 0);
    return R_VALUE(rc) != KERNELRESULT(InvalidEnumValue);
}

static bool isKernel4x(void)
{
    u64 dummy = 0;
    Result rc = svcGetInfo(&dummy, InfoType_InitialProcessIdRange, INVALID_HANDLE, 0);
    return R_VALUE(rc) != KERNELRESULT(InvalidEnumValue);
}

static void getCodeMemoryCapability(void)
{
    if (detectMesosphere()) {
        // Mesosphère allows for same-process code memory usage.
        g_codeMemoryCapability = CodeMemorySameProcess;
    } else if (isKernel5xOrLater()) {
        // On [5.0.0+], the kernel does not allow the creator process of a CodeMemory object
        // to use svcControlCodeMemory on itself, thus returning InvalidMemoryState (0xD401).
        // However the kernel can be patched to support same-process usage of CodeMemory.
        // We can detect that by passing a bad operation and observe if we actually get InvalidEnumValue (0xF001).
        Handle code;
        Result rc = svcCreateCodeMemory(&code, g_heapAddr, 0x1000);
        if (R_SUCCEEDED(rc)) {
            rc = svcControlCodeMemory(code, (CodeMapOperation)-1, 0, 0x1000, 0);
            svcCloseHandle(code);

            if (R_VALUE(rc) == KERNELRESULT(InvalidEnumValue))
                g_codeMemoryCapability = CodeMemorySameProcess;
            else
                g_codeMemoryCapability = CodeMemoryForeignProcess;
        }
    } else if (isKernel4x()) {
        // On [4.0.0-4.1.0] there is no such restriction on same-process CodeMemory usage.
        g_codeMemoryCapability = CodeMemorySameProcess;
    } else {
        // This kernel is too old to support CodeMemory syscalls.
        g_codeMemoryCapability = CodeMemoryUnavailable;
    }
}

void loadNro(void)
{
    NroHeader* header = NULL;
    size_t rw_size=0;
    Result rc=0;

    memcpy((u8*)armGetTls() + 0x100, g_savedTls, 0x100);

    if (g_nroSize > 0)
    {
        // Unmap previous NRO.
        header = &g_nroHeader;
        rw_size = header->segments[2].size + header->bss_size;
        rw_size = (rw_size+0xFFF) & ~0xFFF;

        svcBreak(BreakReason_NotificationOnlyFlag | BreakReason_PreUnloadDll, g_nroAddr, g_nroSize);

        // .text
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[0].file_off, ((u64) g_heapAddr) + header->segments[0].file_off, header->segments[0].size);

        if (R_FAILED(rc))
            diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 24));

        // .rodata
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[1].file_off, ((u64) g_heapAddr) + header->segments[1].file_off, header->segments[1].size);

        if (R_FAILED(rc))
            diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 25));

       // .data + .bss
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[2].file_off, ((u64) g_heapAddr) + header->segments[2].file_off, rw_size);

        if (R_FAILED(rc))
            diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 26));

        svcBreak(BreakReason_NotificationOnlyFlag | BreakReason_PostUnloadDll, g_nroAddr, g_nroSize);

        g_nroAddr = g_nroSize = 0;
    }

    if (g_nextNroPath[0] == '\0')
    {	
		if(*g_launchArgs)
		{
			memset(g_nextArgv, 0, sizeof(g_nextArgv));
			memset(g_nextNroPath, 0, sizeof(g_nextNroPath));
			
			strncpy(g_nextNroPath, g_launchArgs, sizeof(g_nextNroPath) - 2);
			
			for(int i=0; i < sizeof(g_nextNroPath) - 2; i++)
			{
				if(g_nextNroPath[i] == ' ')
				{
					g_nextNroPath[i] = NULL;
					break;
				}
			}
			strncpy(g_nextArgv,    g_launchArgs, sizeof(g_nextArgv) - 2);
		}
		else
		{
			memcpy(g_nextNroPath, DEFAULT_NRO, sizeof(DEFAULT_NRO));
			memcpy(g_nextArgv,    DEFAULT_NRO, sizeof(DEFAULT_NRO));
		}
    }

    memcpy(g_argv, g_nextArgv, sizeof g_argv);

    svcBreak(BreakReason_NotificationOnlyFlag | BreakReason_PreLoadDll, (uintptr_t)g_argv, sizeof(g_argv));

    uint8_t *nrobuf = (uint8_t*) g_heapAddr;

    NroStart*  start  = (NroStart*)  (nrobuf + 0);
    header = (NroHeader*) (nrobuf + sizeof(NroStart));
    uint8_t*   rest   = (uint8_t*)   (nrobuf + sizeof(NroStart) + sizeof(NroHeader));


    rc = fsdevMountSdmc();
    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 404));

    int fd = open(g_nextNroPath, O_RDONLY);
    if (fd < 0)
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 3));

    // Reset NRO path to load hbmenu by default next time.
    g_nextNroPath[0] = '\0';

    if (read(fd, start, sizeof(*start)) != sizeof(*start))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 4));

    if (read(fd, header, sizeof(*header)) != sizeof(*header))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 4));

    if (header->magic != NROHEADER_MAGIC)
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 5));

    size_t rest_size = header->size - (sizeof(NroStart) + sizeof(NroHeader));
    if (read(fd, rest, rest_size) != rest_size)
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 7));

    close(fd);
    fsdevUnmountAll();

    size_t total_size = header->size + header->bss_size;
    total_size = (total_size+0xFFF) & ~0xFFF;

    rw_size = header->segments[2].size + header->bss_size;
    rw_size = (rw_size+0xFFF) & ~0xFFF;

    int i;
    for (i=0; i<3; i++)
    {
        if (header->segments[i].file_off >= header->size || header->segments[i].size > header->size ||
            (header->segments[i].file_off + header->segments[i].size) > header->size)
        {
            diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 6));
        }
    }

    // todo: Detect whether NRO fits into heap or not.

    // Copy header to elsewhere because we're going to unmap it next.
    memcpy(&g_nroHeader, header, sizeof(g_nroHeader));
    header = &g_nroHeader;

    // Map code memory to a new randomized address
    virtmemLock();
    void* map_addr = virtmemFindCodeMemory(total_size, 0);
    rc = svcMapProcessCodeMemory(g_procHandle, (u64)map_addr, (u64)nrobuf, total_size);
    virtmemUnlock();

    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 18));

    // .text
    rc = svcSetProcessMemoryPermission(
        g_procHandle, (u64)map_addr + header->segments[0].file_off, header->segments[0].size, Perm_R | Perm_X);

    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 19));

    // .rodata
    rc = svcSetProcessMemoryPermission(
        g_procHandle, (u64)map_addr + header->segments[1].file_off, header->segments[1].size, Perm_R);

    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 20));

    // .data + .bss
    rc = svcSetProcessMemoryPermission(
        g_procHandle, (u64)map_addr + header->segments[2].file_off, rw_size, Perm_Rw);

    if (R_FAILED(rc))
        diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 21));

    u64 nro_size = header->segments[2].file_off + rw_size;
    u64 nro_heap_start = ((u64) g_heapAddr) + nro_size;
    u64 nro_heap_size  = g_heapSize + (u64) g_heapAddr - (u64) nro_heap_start;

    #define M EntryFlag_IsMandatory

    static ConfigEntry entries[] = {
        { EntryType_MainThreadHandle,     0, {0, 0} },
        { EntryType_ProcessHandle,        0, {0, 0} },
        { EntryType_AppletType,           0, {AppletType_LibraryApplet, 0} },
        { EntryType_OverrideHeap,         M, {0, 0} },
        { EntryType_Argv,                 0, {0, 0} },
        { EntryType_NextLoadPath,         0, {0, 0} },
        { EntryType_LastLoadResult,       0, {0, 0} },
        { EntryType_SyscallAvailableHint, 0, {0xffffffffffffffff, 0x9fc9fff0027ffff} },
        { EntryType_RandomSeed,           0, {0, 0} },
        { EntryType_UserIdStorage,        0, {(u64)(uintptr_t)&g_userIdStorage, 0} },
        { EntryType_HosVersion,           0, {0, 0} },
        { EntryType_EndOfList,            0, {(u64)(uintptr_t)g_noticeText, sizeof(g_noticeText)} }
    };

    ConfigEntry *entry_AppletType = &entries[2];
    ConfigEntry *entry_Syscalls   = &entries[7];

    if (g_isApplication) {
        entry_AppletType->Value[0] = AppletType_SystemApplication;
        entry_AppletType->Value[1] = EnvAppletFlags_ApplicationOverride;
    }

    if (!(g_codeMemoryCapability & BIT(0))) {
        // Revoke access to svcCreateCodeMemory if it's not available.
        entry_Syscalls->Value[0x4B/64] &= ~(1UL << (0x4B%64));
    }

    if (!(g_codeMemoryCapability & BIT(1))) {
        // Revoke access to svcControlCodeMemory if it's not available for same-process usage.
        entry_Syscalls->Value[0x4C/64] &= ~(1UL << (0x4C%64)); // svcControlCodeMemory
    }

    // MainThreadHandle
    entries[0].Value[0] = envGetMainThreadHandle();
    // ProcessHandle
    entries[1].Value[0] = g_procHandle;
    // OverrideHeap
    entries[3].Value[0] = nro_heap_start;
    entries[3].Value[1] = nro_heap_size;
    // Argv
    entries[4].Value[1] = (u64)(uintptr_t)&g_argv[0];
    // NextLoadPath
    entries[5].Value[0] = (u64)(uintptr_t)&g_nextNroPath[0];
    entries[5].Value[1] = (u64)(uintptr_t)&g_nextArgv[0];
    // LastLoadResult
    entries[6].Value[0] = g_lastRet;
    // RandomSeed
    entries[8].Value[0] = randomGet64();
    entries[8].Value[1] = randomGet64();
    // HosVersion
    entries[10].Value[0] = hosversionGet();
    entries[10].Value[1] = hosversionIsAtmosphere() ? 0x41544d4f53504852UL : 0; // 'ATMOSPHR'

    g_nroAddr = (u64)map_addr;
    g_nroSize = nro_size;

    svcBreak(BreakReason_NotificationOnlyFlag | BreakReason_PostLoadDll, g_nroAddr, g_nroSize);

    nroEntrypointTrampoline(&entries[0], -1, g_nroAddr);
    }

static Service g_appletSrv;

static Result _appletCmdNoInOutU64(Service* srv, u64 *out, u32 cmd_id) {
    serviceAssumeDomain(srv);
    return serviceDispatchOut(srv, cmd_id, *out);
}

static Result _appletStorageAccessorRW(Service* srv, size_t ipcbufsize, s64 offset, void* buffer, size_t size, bool rw) {
    serviceAssumeDomain(srv);
    return serviceDispatchIn(srv, rw ? 10 : 11, offset,
        .buffer_attrs = { SfBufferAttr_HipcAutoSelect | (rw ? SfBufferAttr_In : SfBufferAttr_Out) },
        .buffers = { { buffer, size } },
    );
}

static Result _appletGetSessionProxy(Service* srv_out, Handle prochandle, u32 cmd_id) {
    u64 reserved=0;
    serviceAssumeDomain(&g_appletSrv);
    return serviceDispatchIn(&g_appletSrv, cmd_id, reserved,
        .in_send_pid = true,
        .in_num_handles = 1,
        .in_handles = { prochandle },
        .out_num_objects = 1,
        .out_objects = srv_out,
    );
}

static Result _appletCmdGetSession(Service* srv, Service* srv_out, u32 cmd_id) {
    serviceAssumeDomain(srv);
    return serviceDispatch(srv, cmd_id,
        .out_num_objects = 1,
        .out_objects = srv_out,
    );
}

static Result _appletStorageGetSize(AppletStorage *s, s64 *size) {
    Result rc=0;
    Service tmp_srv;//IStorageAccessor

    if (!serviceIsActive(&s->s))
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    rc = _appletCmdGetSession(&s->s, &tmp_srv, 0);//Open
    if (R_FAILED(rc)) return rc;

    rc = _appletCmdNoInOutU64(&tmp_srv, (u64*)size, 0);
    serviceAssumeDomain(&tmp_srv);
    serviceClose(&tmp_srv);

    return rc;
}

static Result _appletPopLaunchParameter(AppletStorage *s, AppletLaunchParameterKind kind) {
    u32 tmp=kind;
    memset(s, 0, sizeof(AppletStorage));
    serviceAssumeDomain(appletGetServiceSession_Functions());
    return serviceDispatchIn(appletGetServiceSession_Functions(), 1, tmp,
        .out_num_objects = 1,
        .out_objects = &s->s,
    );
}

static Result _appletStorageRW(AppletStorage *s, s64 offset, void* buffer, size_t size, bool rw) {
    Result rc=0;
    Service tmp_srv;//IStorageAccessor

    if (!serviceIsActive(&s->s))
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);

    rc = _appletCmdGetSession(&s->s, &tmp_srv, 0);//Open
    if (R_FAILED(rc)) return rc;

    if (R_SUCCEEDED(rc)) rc = _appletStorageAccessorRW(&tmp_srv, tmp_srv.pointer_buffer_size, offset, buffer, size, rw);
    serviceAssumeDomain(&tmp_srv);
    serviceClose(&tmp_srv);

    return rc;
}

static Result _appletStorageRead(AppletStorage *s, s64 offset, void* buffer, size_t size) {
    return _appletStorageRW(s, offset, buffer, size, false);
}

#define AM_BUSY_ERROR 0x19280

void blah(void)
{
	Result rc;
	
	rc = smGetService(&g_appletSrv, "appletOE");
	
	if (R_SUCCEEDED(rc))
	{
        rc = serviceConvertToDomain(&g_appletSrv);
		
		if(R_FAILED(rc))
		{
			//err("serviceConvertToDomain failed");
			return;
		}
    }
	else
	{
		//err("smGetService failed");
		return;
	}
	
	do
	{
		rc = _appletGetSessionProxy(appletGetServiceSession_Proxy(), CUR_PROCESS_HANDLE, 0);
		
		if (rc == AM_BUSY_ERROR)
		{
            svcSleepThread(10000000);
        }
	}
	while(rc == AM_BUSY_ERROR);
	
	if (R_FAILED(rc)) {
		//err("appletGetSessionProxy failed");
		serviceClose(&g_appletSrv);
		return;
	}
	
	rc = _appletCmdGetSession(appletGetServiceSession_Proxy(), appletGetServiceSession_Functions(), 20);
	
	if (R_FAILED(rc)) {
		serviceClose(appletGetServiceSession_Proxy());
		serviceClose(&g_appletSrv);
		//err("_appletCmdGetSession failed");
	}
	
	AppletStorage s;
	memset(&g_launchArgs, 0, sizeof(g_launchArgs));
	
	if(!_appletPopLaunchParameter(&s, AppletLaunchParameterKind_UserChannel))
	{			
		s64 sz = 0;
		
		if(!_appletStorageGetSize(&s, &sz))
		{
			if(sz > sizeof(g_launchArgs))
			{
				sz = sizeof(g_launchArgs)-2;
			}
			
			if(!_appletStorageRead(&s, 0, g_launchArgs, sz))
			{
				//err("succeeded");
				//memset(&g_launchArgs, 0, sizeof(g_launchArgs));
			}
			else
			{
				//err("appletStorageRead failed");
			}
		}
		else
		{
			//err("appletStorageGetSize failed");
		}
		
		appletStorageClose(&s);
	}
	else
	{
		//err("appletPopLaunchParameter failed");
	}
	
	serviceClose(appletGetServiceSession_Functions());
	serviceClose(appletGetServiceSession_Proxy());
    serviceClose(&g_appletSrv);
}

int main(int argc, char **argv)
{
    memcpy(g_savedTls, (u8*)armGetTls() + 0x100, 0x100);
	
	auto rc = fsdevMountSdmc();

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 404));
	
	
	blah();

    getIsApplication();
    getIsAutomaticGameplayRecording();
    smExit(); // Close SM as we don't need it anymore.
    setupHbHeap();
    getOwnProcessHandle();
    getCodeMemoryCapability();
    loadNro();

    diagAbortWithResult(MAKERESULT(Module_HomebrewLoader, 8));
    return 0;
}
