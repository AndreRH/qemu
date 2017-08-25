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
    /* TODO: 32 bit version. */
    asm volatile( "syscall\n"
            : /* no output */
            : "c"(call)
            : "memory");
}

#define QEMU_SYSCALL_ID(a) ((QEMU_CURRENT_DLL << 32ULL) | (a))

#ifndef QEMU_DLL_GUEST

struct qemu_ops
{
    uint64_t (*qemu_execute)(const void *code, uint64_t rcx);
    BOOL (*qemu_FreeLibrary)(HMODULE module);
    DWORD (*qemu_GetModuleFileName)(HMODULE module, WCHAR *filename, DWORD size);
    HMODULE (*qemu_GetModuleHandleEx)(DWORD flags, const WCHAR *name);
    const void *(*qemu_GetProcAddress)(HMODULE module, const char *name);
    void *(*qemu_getTEB)(void);
    HMODULE (*qemu_LoadLibrary)(const WCHAR *name, DWORD flags);
    void (*qemu_set_except_handler)(uint64_t handler);
    void (*qemu_set_call_entry)(uint64_t call_entry);
    BOOL (*qemu_FindEntryForAddress)(void *addr, HMODULE *mod);
    BOOL (*qemu_DisableThreadLibraryCalls)(HMODULE mod);
    BOOL (*qemu_get_ldr_module)(HANDLE process, HMODULE mod, void **ldr);
    void *(*qemu_RtlPcToFileHeader)(void *pc, void **address);
    BOOL (*qemu_DllMain)(DWORD reason, void *reserved);
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
