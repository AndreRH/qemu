#ifndef QEMU_PE_H
#define QEMU_PE_H

HMODULE qemu_LoadLibraryA(const char *name);
HMODULE qemu_GetModuleHandleEx(DWORD flags, const char *name);
const void *qemu_GetProcAddress(HMODULE module, const char *name);
BOOL qemu_FreeLibrary(HMODULE module);

struct qemu_pe_image
{
    void *entrypoint;
    DWORD stack_reserve, stack_commit;
};

void qemu_get_image_info(const HMODULE module, struct qemu_pe_image *info);

#endif
