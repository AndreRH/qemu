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
    /* TODO: 32 bit version.
     *
     * Call should already be in rcx due to the calling convention.
     * But the compiler may do something between function entry and
     * the syscall. Move call into rcx and let the optimizer fix
     * the redundant copy.
     *
     * FIXME 2: Apparently the optimizer doesn't know what I am
     * doing here and optimizes everything except the syscall and
     * retq away from most functions. */
    asm volatile("mov %0, %%rcx\n"
            "syscall\n"
            : /* no output - really? call is modified. */
            : "g"(call)
            : "%rcx", "memory");
}

#define QEMU_SYSCALL_ID(a) ((QEMU_CURRENT_DLL << 32ULL) | (a))

#ifndef QEMU_DLL_GUEST

struct qemu_ops
{
    uint64_t (*qemu_execute)(const void *code, uint64_t rcx);
    BOOL (*qemu_FreeLibrary)(HMODULE module);
    HMODULE (*qemu_GetModuleHandleEx)(DWORD flags, const char *name);
    const void *(*qemu_GetProcAddress)(HMODULE module, const char *name);
    HMODULE (*qemu_LoadLibrary)(const char *name);
};

typedef void (*syscall_handler)(struct qemu_syscall *call);
typedef const syscall_handler *(WINAPI *syscall_lib_register)(const struct qemu_ops *ops, uint32_t *dll_num);

/* For now this is just a placeholder that is used to mark places where we're taking a guest pointer and
 * need a host pointer or vice versa. It has the practical purpose of shutting up the int to ptr conversion
 * warning. If we ever have a diverging address space this will probably call into qemu_ops. */
#define QEMU_G2H(a)((void *)(a))
#define QEMU_H2G(a)((uint64_t)(a))

#endif

#endif
