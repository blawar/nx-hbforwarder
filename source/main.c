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

static NsApplicationControlData g_applicationControlData;
static bool g_isAutomaticGameplayRecording = 0;
static bool g_smCloseWorkaround = false;

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

extern void* __stack_top;//Defined in libnx.
#define STACK_SIZE 0x100000 //Change this if main-thread stack size ever changes.

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

    rc = smInitialize();
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 1));

    rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        SetSysFirmwareVersion fw;
        rc = setsysGetFirmwareVersion(&fw);
        if (R_SUCCEEDED(rc))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        readSetting("applet_heap_size", &g_appletHeapSize, sizeof(g_appletHeapSize));
        readSetting("applet_heap_reservation_size", &g_appletHeapReservationSize, sizeof(g_appletHeapReservationSize));
        setsysExit();
    }

    rc = fsInitialize();
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 2));
}

void __wrap_exit(void)
{
    // exit() effectively never gets called, so let's stub it out.
    fatalThrow(MAKERESULT(Module_HomebrewLoader, 39));
}

static void*  g_heapAddr;
static size_t g_heapSize;

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
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 9));

    g_heapAddr = addr;
    g_heapSize = size;
}

static Handle g_procHandle;

static void procHandleReceiveThread(void* arg)
{
    Handle session = (Handle)(uintptr_t)arg;
    Result rc;

    void* base = armGetTls();
    hipcMakeRequestInline(base);

    s32 idx = 0;
    rc = svcReplyAndReceive(&idx, &session, 1, INVALID_HANDLE, UINT64_MAX);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 15));

    HipcParsedRequest r = hipcParseRequest(base);
    if (r.meta.num_copy_handles != 1)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 17));

    g_procHandle = r.data.copy_handles[0];
    svcCloseHandle(session);
}

//Gets the PID of the process with application_type==APPLICATION in the NPDM, then sets g_isApplication if it matches the current PID.
static void getIsApplication(void) {
    Result rc=0;
    u64 cur_pid=0, app_pid=0;

    g_isApplication = 0;

    rc = svcGetProcessId(&cur_pid, CUR_PROCESS_HANDLE);
    if (R_FAILED(rc)) return;

    rc = pmshellInitialize();

    if (R_SUCCEEDED(rc)) {
        rc = pmshellGetApplicationProcessIdForShell(&app_pid);
        pmshellExit();
    }

    if (R_SUCCEEDED(rc) && cur_pid == app_pid) g_isApplication = 1;
}

//Gets the control.nacp for the current title id, and then sets g_isAutomaticGameplayRecording if less memory should be allocated.
static void getIsAutomaticGameplayRecording(void) {
    if (hosversionAtLeast(5,0,0) && g_isApplication) {
        Result rc=0;
        u64 cur_tid=0;

        rc = svcGetInfo(&cur_tid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
        if (R_FAILED(rc)) return;

        g_isAutomaticGameplayRecording = 0;

        rc = nsInitialize();

        if (R_SUCCEEDED(rc)) {
            size_t dummy;
            rc = nsGetApplicationControlData(0x1, cur_tid, &g_applicationControlData, sizeof(g_applicationControlData), &dummy);
            nsExit();
        }

        if (R_SUCCEEDED(rc) && g_applicationControlData.nacp.video_capture_mode == 2) g_isAutomaticGameplayRecording = 1;
    }
}

static void getOwnProcessHandle(void)
{
    Result rc;

    Handle server_handle, client_handle;
    rc = svcCreateSession(&server_handle, &client_handle, 0, 0);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 12));

    Thread t;
    rc = threadCreate(&t, &procHandleReceiveThread, (void*)(uintptr_t)server_handle, NULL, 0x1000, 0x20, 0);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 10));

    rc = threadStart(&t);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 13));

    hipcMakeRequestInline(armGetTls(),
        .num_copy_handles = 1,
    ).copy_handles[0] = CUR_PROCESS_HANDLE;

    svcSendSyncRequest(client_handle);
    svcCloseHandle(client_handle);

    threadWaitForExit(&t);
    threadClose(&t);
}

void err(const char* msg)
{
#ifdef DEBUG
	FILE* f = fopen("sdmc:/hbl.log", "w+");
	fwrite(msg, strlen(msg), 1, f);
	fclose(f);
#endif
}

void loadNro(void)
{
    NroHeader* header = NULL;
    size_t rw_size=0;
    Result rc=0;

    if (g_smCloseWorkaround) {
        // For old applications, wait for SM to handle closing the SM session from this process.
        // If we don't do this, smInitialize will fail once eventually used later.
        // This is caused by a bug in old versions of libnx that was fixed in commit 68a77ac950.
        g_smCloseWorkaround = false;
        svcSleepThread(1000000000);
    }

    memcpy((u8*)armGetTls() + 0x100, g_savedTls, 0x100);

    if (g_nroSize > 0)
    {
        // Unmap previous NRO.
        header = &g_nroHeader;
        rw_size = header->segments[2].size + header->bss_size;
        rw_size = (rw_size+0xFFF) & ~0xFFF;

        // .text
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[0].file_off, ((u64) g_heapAddr) + header->segments[0].file_off, header->segments[0].size);

        if (R_FAILED(rc))
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 24));

        // .rodata
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[1].file_off, ((u64) g_heapAddr) + header->segments[1].file_off, header->segments[1].size);

        if (R_FAILED(rc))
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 25));

       // .data + .bss
        rc = svcUnmapProcessCodeMemory(
            g_procHandle, g_nroAddr + header->segments[2].file_off, ((u64) g_heapAddr) + header->segments[2].file_off, rw_size);

        if (R_FAILED(rc))
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 26));

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

    uint8_t *nrobuf = (uint8_t*) g_heapAddr;

    NroStart*  start  = (NroStart*)  (nrobuf + 0);
    header = (NroHeader*) (nrobuf + sizeof(NroStart));
    uint8_t*   rest   = (uint8_t*)   (nrobuf + sizeof(NroStart) + sizeof(NroHeader));


    int fd = open(g_nextNroPath, O_RDONLY);
    if (fd < 0)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 3));

    // Reset NRO path to load hbmenu by default next time.
    g_nextNroPath[0] = '\0';

    if (read(fd, start, sizeof(*start)) != sizeof(*start))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 4));

    if (read(fd, header, sizeof(*header)) != sizeof(*header))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 4));

    if (header->magic != NROHEADER_MAGIC)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 5));

    size_t rest_size = header->size - (sizeof(NroStart) + sizeof(NroHeader));
    if (read(fd, rest, rest_size) != rest_size)
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 7));

    close(fd);
    fsdevUnmountAll();

    size_t total_size = header->size + header->bss_size;
    total_size = (total_size+0xFFF) & ~0xFFF;

    rw_size = header->segments[2].size + header->bss_size;
    rw_size = (rw_size+0xFFF) & ~0xFFF;

    bool has_mod0 = false;
    if (start->mod_offset > 0 && start->mod_offset <= (total_size-0x24)) // Validate MOD0 offset
        has_mod0 = *(uint32_t*)(nrobuf + start->mod_offset) == 0x30444F4D; // Validate MOD0 header

    int i;
    for (i=0; i<3; i++)
    {
        if (header->segments[i].file_off >= header->size || header->segments[i].size > header->size ||
            (header->segments[i].file_off + header->segments[i].size) > header->size)
        {
            fatalThrow(MAKERESULT(Module_HomebrewLoader, 6));
        }
    }

    // todo: Detect whether NRO fits into heap or not.

    // Copy header to elsewhere because we're going to unmap it next.
    memcpy(&g_nroHeader, header, sizeof(g_nroHeader));
    header = &g_nroHeader;

    u64 map_addr;

    do {
        map_addr = randomGet64() & 0xFFFFFF000ull;
        rc = svcMapProcessCodeMemory(g_procHandle, map_addr, (u64)nrobuf, total_size);

    } while (rc == 0xDC01 || rc == 0xD401);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 18));

    // .text
    rc = svcSetProcessMemoryPermission(
        g_procHandle, map_addr + header->segments[0].file_off, header->segments[0].size, Perm_R | Perm_X);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 19));

    // .rodata
    rc = svcSetProcessMemoryPermission(
        g_procHandle, map_addr + header->segments[1].file_off, header->segments[1].size, Perm_R);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 20));

    // .data + .bss
    rc = svcSetProcessMemoryPermission(
        g_procHandle, map_addr + header->segments[2].file_off, rw_size, Perm_Rw);

    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_HomebrewLoader, 21));

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
        { EntryType_SyscallAvailableHint, 0, {0xffffffffffffffff, 0x9fc1fff0007ffff} },
        { EntryType_RandomSeed,           0, {0, 0} },
        { EntryType_UserIdStorage,        0, {(u64)(uintptr_t)&g_userIdStorage, 0} },
        { EntryType_HosVersion,           0, {0, 0} },
        { EntryType_EndOfList,            0, {(u64)(uintptr_t)g_noticeText, sizeof(g_noticeText)} }
    };

    ConfigEntry *entry_AppletType = &entries[2];

    if (g_isApplication) {
        entry_AppletType->Value[0] = AppletType_SystemApplication;
        entry_AppletType->Value[1] = EnvAppletFlags_ApplicationOverride;
    }

    // MainThreadHandle
    entries[0].Value[0] = envGetMainThreadHandle();
    // ProcessHandle
    entries[1].Value[0] = g_procHandle;
    // OverrideHeap
    entries[3].Value[0] = nro_heap_start;
    entries[3].Value[1] = nro_heap_size;
    // Argv
    entries[4].Value[1] = (u64) &g_argv[0];
    // NextLoadPath
    entries[5].Value[0] = (u64) &g_nextNroPath[0];
    entries[5].Value[1] = (u64) &g_nextArgv[0];
    // LastLoadResult
    entries[6].Value[0] = g_lastRet;
    // RandomSeed
    entries[8].Value[0] = randomGet64();
    entries[8].Value[1] = randomGet64();
    // HosVersion
    entries[10].Value[0] = hosversionGet();

    u64 entrypoint = map_addr;

    g_nroAddr = map_addr;
    g_nroSize = nro_size;

    memset(__stack_top - STACK_SIZE, 0, STACK_SIZE);

    if (!has_mod0) {
        // Apply sm-close workaround to NROs which do not contain a valid MOD0 header.
        // This heuristic is based on the fact that MOD0 support was added very shortly after
        // the fix for the sm-close bug (in fact, two commits later).
        g_smCloseWorkaround = true;
    }

    extern NORETURN void nroEntrypointTrampoline(u64 entries_ptr, u64 handle, u64 entrypoint);
    nroEntrypointTrampoline((u64) entries, -1, entrypoint);
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

void initArguments(void)
{
	Result rc;

	rc = smGetService(&g_appletSrv, "appletOE");

	if (R_SUCCEEDED(rc))
	{
        rc = serviceConvertToDomain(&g_appletSrv);

		if(R_FAILED(rc))
		{
			err("serviceConvertToDomain failed");
			return;
		}
    }
	else
	{
		err("smGetService failed");
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
		err("appletGetSessionProxy failed");
		serviceClose(&g_appletSrv);
		return;
	}

	rc = _appletCmdGetSession(appletGetServiceSession_Proxy(), appletGetServiceSession_Functions(), 20);

	if (R_FAILED(rc)) {
		serviceClose(appletGetServiceSession_Proxy());
		serviceClose(&g_appletSrv);
		err("_appletCmdGetSession failed");
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

			if(R_SUCCEEDED(_appletStorageRead(&s, 0, g_launchArgs, sz)))
			{
			}
			else
			{
				err("appletStorageRead failed");
			}
		}
		else
		{
			err("appletStorageGetSize failed");
		}

		appletStorageClose(&s);
	}
	else
	{
		err("appletPopLaunchParameter failed");
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

	initArguments();

    getIsApplication();
    getIsAutomaticGameplayRecording();
    smExit(); // Close SM as we don't need it anymore.
    setupHbHeap();
    getOwnProcessHandle();
    loadNro();

    fatalThrow(MAKERESULT(Module_HomebrewLoader, 8));
    return 0;
}
