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
    HMODULE (*qemu_GetModuleHandleEx)(DWORD flags, const char *name);
    const void *(*qemu_GetProcAddress)(HMODULE module, const char *name);
    BOOL (*qemu_FreeLibrary)(HMODULE module);
    uint64_t (*qemu_execute)(const void *code, uint64_t rcx);
};

typedef void (*syscall_handler)(struct qemu_syscall *call);
typedef const syscall_handler *(WINAPI *syscall_lib_register)(const struct qemu_ops *ops, uint32_t *dll_num);

/* For now this is just a placeholder that is used to mark places where we're taking a guest pointer and
 * need a host pointer. It has the practical purpose of shutting up the int to ptr conversion warning. If
 * we ever have a diverging address space this will probably call into qemu_ops. */
#define QEMU_G2H(a)((void *)(a))

#endif

#endif
