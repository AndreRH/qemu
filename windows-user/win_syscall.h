#ifndef QEMU_WIN_SYSCALL_H
#define QEMU_WIN_SYSCALL_H

#include "windows-user-services.h"

BOOL load_host_dlls(BOOL load_msvcrt);
void do_syscall(struct qemu_syscall *call);
uint64_t qemu_execute(const void *code, uint64_t rcx);
BOOL qemu_DllMain(DWORD reason, void *reserved);
NTSTATUS qemu_set_context(HANDLE thread, void *context);

#endif
