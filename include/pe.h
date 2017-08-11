#ifndef QEMU_PE_H
#define QEMU_PE_H

HMODULE qemu_LoadLibrary(const WCHAR *name);
DWORD qemu_GetModuleFileName(HMODULE module, WCHAR *filename, DWORD size);
HMODULE qemu_GetModuleHandleEx(DWORD flags, const WCHAR *name);
const void *qemu_GetProcAddress(HMODULE module, const char *name);
BOOL qemu_FreeLibrary(HMODULE module);
BOOL qemu_FindEntryForAddress(void *addr, HMODULE *mod);

struct qemu_pe_image
{
    void *entrypoint;
    DWORD stack_reserve, stack_commit;
};

void qemu_get_image_info(const HMODULE module, struct qemu_pe_image *info);
BOOL qemu_call_process_init(void);

#endif
