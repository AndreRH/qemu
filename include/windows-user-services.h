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

#define QEMU_SYSCALL_ID(a) ((QEMU_CURRENT_DLL << 32ULL) | (a))

static inline uint64_t guest_HANDLE_g2h(HANDLE h)
{
    /* ~0 == Invalid handle == current process, ~1 == current thread, ~3 == current process token,
     * ~4 == GetCurrentThreadToken(), ~5 == GetCurrentThreadEffectiveToken() */
    if (h == INVALID_HANDLE_VALUE || h == (HANDLE)~(ULONG_PTR)1 || h == (HANDLE)~(ULONG_PTR)3
            || h == (HANDLE)~(ULONG_PTR)4 || h == (HANDLE)~(ULONG_PTR)5)
        return (LONG_PTR)h;
    else
        return (ULONG_PTR)h;
}

#ifndef QEMU_DLL_GUEST

#include <winternl.h>

typedef DWORD qemu_ptr, qemu_handle;

typedef struct _CURDIR32
{
    UNICODE_STRING32 DosPath;
    qemu_ptr Handle;
} CURDIR32, *PCURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    ULONG               AllocationSize;
    ULONG               Size;
    ULONG               Flags;
    ULONG               DebugFlags;
    qemu_handle         ConsoleHandle;
    ULONG               ConsoleFlags;
    qemu_handle         hStdInput;
    qemu_handle         hStdOutput;
    qemu_handle         hStdError;
    CURDIR32            CurrentDirectory;
    UNICODE_STRING32    DllPath;
    UNICODE_STRING32    ImagePathName;
    UNICODE_STRING32    CommandLine;
    qemu_ptr            Environment;
    ULONG               dwX;
    ULONG               dwY;
    ULONG               dwXSize;
    ULONG               dwYSize;
    ULONG               dwXCountChars;
    ULONG               dwYCountChars;
    ULONG               dwFillAttribute;
    ULONG               dwFlags;
    ULONG               wShowWindow;
    UNICODE_STRING32    WindowTitle;
    UNICODE_STRING32    Desktop;
    UNICODE_STRING32    ShellInfo;
    UNICODE_STRING32    RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct tagRTL_BITMAP32 {
    ULONG       SizeOfBitMap; /* Number of bits in the bitmap */
    qemu_ptr    Buffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP32, *PRTL_BITMAP32;

struct qemu_ops
{
    uint64_t (*qemu_execute)(const void *code, uint64_t rcx);
    BOOL (*qemu_FreeLibrary)(HMODULE module);
    DWORD (*qemu_GetModuleFileName)(HMODULE module, WCHAR *filename, DWORD size);
    HMODULE (*qemu_GetModuleHandleEx)(DWORD flags, const WCHAR *name);
    NTSTATUS (*qemu_LdrGetProcedureAddress)(HMODULE module, const ANSI_STRING *name, ULONG ord, PVOID *address);
    void *(*qemu_getTEB)(void);
    TEB32 *(*qemu_getTEB32)(void);
    NTSTATUS (*qemu_LdrLoadDll)(LPCWSTR path_name, DWORD flags, const UNICODE_STRING *libname, HMODULE* hModule);
    void (*qemu_set_except_handler)(uint64_t handler);
    void (*qemu_set_call_entry)(uint64_t call_entry);
    BOOL (*qemu_FindEntryForAddress)(void *addr, HMODULE *mod);
    NTSTATUS (*qemu_LdrDisableThreadCalloutsForDll)(HMODULE mod);
    void *(*qemu_LdrResolveDelayLoadedAPI)(void* base, const IMAGE_DELAYLOAD_DESCRIPTOR* desc,
            void *dllhook, void *syshook, IMAGE_THUNK_DATA* addr, ULONG flags);
    BOOL (*qemu_get_ldr_module)(HANDLE process, HMODULE mod, void **ldr);
    void *(*qemu_RtlPcToFileHeader)(void *pc, void **address);
    NTSTATUS (*qemu_LdrGetDllHandle)(LPCWSTR load_path, ULONG flags, const UNICODE_STRING *name, HMODULE *base);
    BOOL (*qemu_DllMain)(DWORD reason, void *reserved);
    NTSTATUS (*qemu_set_context)(HANDLE thread, void *ctx);
    HMODULE (*qemu_module_g2h)(uint64_t guest);
    uint64_t (*qemu_module_h2g)(HMODULE host);
    const WCHAR *(*qemu_getpath)(void);
};

typedef void (*syscall_handler)(struct qemu_syscall *call);
typedef const syscall_handler *(WINAPI *syscall_lib_register)(const struct qemu_ops *ops, uint32_t *dll_num);

/* For now this is just a placeholder that is used to mark places where we're taking a guest pointer and
 * need a host pointer or vice versa. It has the practical purpose of shutting up the int to ptr conversion
 * warning. If we ever have a diverging address space this will probably call into qemu_ops. */
#define QEMU_G2H(a)((void *)(a))
#define QEMU_H2G(a)((uint64_t)(a))

#else

static inline void qemu_syscall(struct qemu_syscall *call)
{
    asm volatile( "syscall\n"
            : /* no output */
            : "c"(call)
            : "memory");
}

#endif

#endif
