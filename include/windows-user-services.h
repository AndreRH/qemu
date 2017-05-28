#ifndef QEMU_WINDOWS_USER_SERVICES_H
#define QEMU_WINDOWS_USER_SERVICES_H

#include <stdint.h>

struct qemu_syscall
{
    uint64_t id;
    union
    {
        uint64_t iret;
        float fret;
        double dret;
    };
};

static inline void qemu_syscall(struct qemu_syscall *call)
{
    /* TODO: Figure out how to store the call ptr in %rax */
    /* TODO2: Use an interrupt instruction for win32 */
    asm("syscall");
}

#define QEMU_SYSCALL_ID(a) ((QEMU_CURRENT_DLL << 32ULL) | (a))

#ifndef QEMU_DLL_GUEST
/* typedef the register export */
/* typedef the host-side call implementation function */
/* typedef the syscall array */

struct qemu_op
{
    void *register_dll;
    void *load_library;
    void *get_proc_address;
    /* etc */
};
#endif

#endif
