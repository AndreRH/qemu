#ifndef QEMU_PE_H
#define QEMU_PE_H

#define DEFAULT_STACK_SIZE 1024 * 1024

HMODULE qemu_LoadLibrary(const WCHAR *name, DWORD flags);
DWORD qemu_GetModuleFileName(HMODULE module, WCHAR *filename, DWORD size);
HMODULE qemu_GetModuleHandleEx(DWORD flags, const WCHAR *name);
const void *qemu_GetProcAddress(HMODULE module, const char *name);
BOOL qemu_FreeLibrary(HMODULE module);
BOOL qemu_FindEntryForAddress(void *addr, HMODULE *mod);
BOOL qemu_DisableThreadLibraryCalls(HMODULE mod);
BOOL qemu_get_ldr_module(HANDLE process, HMODULE mod, void **ldr);
void *qemu_RtlPcToFileHeader(void *pc, void **address);
BOOL qemu_is_32_bit_exe(const WCHAR *name);

TEB *qemu_getTEB(void);
TEB32 *qemu_getTEB32(void);

NTSTATUS qemu_LdrInitializeThunk(void);
/* Not sure exactly if I'll ever need those, but they are copypasted along with the rest
 * of ntdll/loader.c, and they sound important, so keep them as dead code for now. */
NTSTATUS MODULE_DllThreadAttach( LPVOID lpReserved );
NTSTATUS WINAPI qemu_LdrEnumerateLoadedModules( void *unknown, void *callback, void *context );
void* WINAPI qemu_LdrResolveDelayLoadedAPI( void* base, const IMAGE_DELAYLOAD_DESCRIPTOR* desc,
                                       PDELAYLOAD_FAILURE_DLL_CALLBACK dllhook, void* syshook,
                                       IMAGE_THUNK_DATA* addr, ULONG flags );

struct qemu_pe_image
{
    void *entrypoint;
    DWORD stack_reserve, stack_commit;
};

void qemu_get_image_info(const HMODULE module, struct qemu_pe_image *info);
BOOL qemu_call_process_init(void);
void qemu_loader_thread_init(void);

extern BOOL (WINAPI *pPathRemoveFileSpecA)(char *path);
extern BOOL (WINAPI *pPathRemoveFileSpecW)(WCHAR *path);

#endif
