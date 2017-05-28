#ifndef QEMU_PE_H
#define QEMU_PE_H

HMODULE qemu_LoadLibraryA(const char *name);

struct qemu_pe_image
{
    void *entrypoint;
    DWORD stack_reserve, stack_commit;
};

void qemu_get_image_info(const HMODULE module, struct qemu_pe_image *info);

#endif
