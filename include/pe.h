#ifndef QEMU_PE_H
#define QEMU_PE_H

#define DEFAULT_STACK_SIZE 1024 * 1024

HMODULE qemu_LoadLibrary(const WCHAR *name, DWORD flags);
DWORD qemu_GetModuleFileName(HMODULE module, WCHAR *filename, DWORD size);
HMODULE qemu_GetModuleHandleEx(DWORD flags, const WCHAR *name);
const void *qemu_GetProcAddress(HMODULE module, const char *name);
BOOL qemu_FreeLibrary(HMODULE module);
BOOL qemu_FindEntryForAddress(void *addr, HMODULE *mod);
NTSTATUS WINAPI hook_LdrFindEntryForAddress(const void* addr, PLDR_DATA_TABLE_ENTRY* pmod);
BOOL qemu_DisableThreadLibraryCalls(HMODULE mod);
BOOL qemu_get_ldr_module(HANDLE process, HMODULE mod, void **ldr);
void *qemu_RtlPcToFileHeader(void *pc, void **address);
NTSTATUS qemu_LdrGetDllHandle( LPCWSTR load_path, ULONG flags, const UNICODE_STRING *name, HMODULE *base );
BOOL qemu_get_exe_properties(const WCHAR *path, WCHAR *exename, size_t name_len, BOOL *is_32_bit,
        BOOL *large_address_aware, DWORD_PTR *base, DWORD_PTR *size);
HMODULE qemu_ldr_module_g2h(uint64_t guest);
uint64_t qemu_ldr_module_h2g(HMODULE host);
void* qemu_LdrResolveDelayLoadedAPI( void* base, const IMAGE_DELAYLOAD_DESCRIPTOR* desc,
        void *dllhook, void *syshook, IMAGE_THUNK_DATA *addr, ULONG flags );
NTSTATUS qemu_LdrLoadDll(LPCWSTR path_name, DWORD flags,
        const UNICODE_STRING *libname, HMODULE* hModule);

TEB *qemu_getTEB(void);
TEB32 *qemu_getTEB32(void);

NTSTATUS qemu_LdrInitializeThunk(void);
/* Not sure exactly if I'll ever need those, but they are copypasted along with the rest
 * of ntdll/loader.c, and they sound important, so keep them as dead code for now. */
NTSTATUS MODULE_DllThreadAttach( LPVOID lpReserved );
NTSTATUS WINAPI qemu_LdrEnumerateLoadedModules( void *unknown, void *callback, void *context );

struct qemu_pe_image
{
    void *entrypoint;
    DWORD stack_reserve, stack_commit;
};

void qemu_get_image_info(const HMODULE module, struct qemu_pe_image *info);
BOOL qemu_call_process_init(void);
void qemu_loader_thread_init(void);
void qemu_loader_thread_stop(void);

extern BOOL my_PathRemoveFileSpecA(char *path);
extern BOOL my_PathRemoveFileSpecW(WCHAR *path);

#endif
