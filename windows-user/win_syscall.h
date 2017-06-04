#ifndef QEMU_WIN_SYSCALL_H
#define QEMU_WIN_SYSCALL_H

#include "windows-user-services.h"

BOOL load_host_dlls(void);
void do_syscall(struct qemu_syscall *call);
uint64_t qemu_execute(const void *code, uint64_t rcx);

#endif
