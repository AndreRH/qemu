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

struct qemu_ops
{
    void *load_library;
    void *get_proc_address;
};

typedef void (*syscall_handler)(struct qemu_syscall *call);
typedef const syscall_handler *(WINAPI *syscall_lib_register)(const struct qemu_ops *ops, uint32_t *dll_num);

#endif

#endif
