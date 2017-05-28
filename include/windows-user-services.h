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
    /* TODO: 32 bit version */
    asm("mov %%rax, %0\n"
            "syscall\n"
            : /* no output - really? call is modified. */
            : "g"(call)
            : "%rax");
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
