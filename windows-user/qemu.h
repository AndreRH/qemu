#ifndef QEMU_H
#define QEMU_H

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

#include "hostdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"

#undef DEBUG_REMAP
#ifdef DEBUG_REMAP
#endif /* DEBUG_REMAP */

#include "exec/user/abitypes.h"

#include "exec/user/thunk.h"
#include "syscall_defs.h"
#include "target_syscall.h"
#include "exec/gdbstub.h"
#include "qemu/queue.h"

/* Include target-specific struct and function definitions;
 * they may need access to the target-independent structures
 * above, so include them last.
 */
#include "target_cpu.h"
#include "target_signal.h"
#include "target_structs.h"

int target_mprotect(abi_ulong start, abi_ulong len, int prot);
void mmap_fork_start(void);
void mmap_fork_end(int child);

#define VERIFY_READ 0
#define VERIFY_WRITE 1 /* implies read access */

static inline void *lock_user(int type, abi_ulong guest_addr, long len, int copy)
{
//     qemu_log("lock_user\n");
    return g2h(guest_addr);
}

static inline void unlock_user(void *host_ptr, abi_ulong guest_addr,
                               long len)
{
//     qemu_log("unlock_user\n");
}

struct image_info
{
        abi_ulong       load_bias;
        abi_ulong       load_addr;
        abi_ulong       start_code;
        abi_ulong       end_code;
        abi_ulong       start_data;
        abi_ulong       end_data;
        abi_ulong       start_brk;
        abi_ulong       brk;
        abi_ulong       start_mmap;
        abi_ulong       start_stack;
        abi_ulong       stack_limit;
        abi_ulong       entry;
        abi_ulong       code_offset;
        abi_ulong       data_offset;
        abi_ulong       saved_auxv;
        abi_ulong       auxv_len;
        abi_ulong       arg_start;
        abi_ulong       arg_end;
        abi_ulong       arg_strings;
        abi_ulong       env_strings;
        abi_ulong       file_string;
        uint32_t        elf_flags;
	int		personality;
#ifdef CONFIG_USE_FDPIC
        abi_ulong       loadmap_addr;
        uint16_t        nsegs;
        void           *loadsegs;
        abi_ulong       pt_dynamic_addr;
        struct image_info *other_info;
#endif
};

/* NOTE: we force a big alignment so that the stack stored after is
   aligned too */
typedef struct TaskState
{
    pid_t ts_tid;     /* tid (or pid) of this task */
#ifdef TARGET_ARM
# ifdef TARGET_ABI32
    /* FPA state */
    FPA11 fpa;
# endif
    int swi_errno;
#endif
#ifdef TARGET_UNICORE32
    int swi_errno;
#endif
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    abi_ulong target_v86;
    struct vm86_saved_state vm86_saved_regs;
    struct target_vm86plus_struct vm86plus;
    uint32_t v86flags;
    uint32_t v86mask;
#endif
    abi_ulong child_tidptr;
#ifdef TARGET_M68K
    int sim_syscalls;
    abi_ulong tp_value;
#endif
#if defined(TARGET_ARM) || defined(TARGET_M68K) || defined(TARGET_UNICORE32)
    /* Extra fields for semihosted binaries.  */
    abi_ulong heap_base;
    abi_ulong heap_limit;
#endif
    abi_ulong stack_base;
    int used; /* non zero if used */
    struct image_info *info;
    struct linux_binprm *bprm;

//     struct emulated_sigtable sync_signal;
//     struct emulated_sigtable sigtab[TARGET_NSIG];
    /* This thread's signal mask, as requested by the guest program.
     * The actual signal mask of this thread may differ:
     *  + we don't let SIGSEGV and SIGBUS be blocked while running guest code
     *  + sometimes we block all signals to avoid races
     */
    sigset_t signal_mask;
    /* The signal mask imposed by a guest sigsuspend syscall, if we are
     * currently in the middle of such a syscall
     */
    sigset_t sigsuspend_mask;
    /* Nonzero if we're leaving a sigsuspend and sigsuspend_mask is valid. */
    int in_sigsuspend;

    /* Nonzero if process_pending_signals() needs to do something (either
     * handle a pending signal or unblock signals).
     * This flag is written from a signal handler so should be accessed via
     * the atomic_read() and atomic_write() functions. (It is not accessed
     * from multiple threads.)
     */
    int signal_pending;

} __attribute__((aligned(16))) TaskState;

extern unsigned long last_brk;

extern __thread CPUState *thread_cpu;

static inline void *my_alloc(size_t s)
{
    return HeapAlloc(GetProcessHeap(), 0, s);
}

static inline void my_free(void *p)
{
    HeapFree(GetProcessHeap(), 0, p);
}

void signal_init(void);

extern PEB guest_PEB;

#define QEMU_CONTEXT_AMD64   0x00100000

#define QEMU_CONTEXT_CONTROL   (QEMU_CONTEXT_AMD64 | 0x0001)
#define QEMU_CONTEXT_INTEGER   (QEMU_CONTEXT_AMD64 | 0x0002)
#define QEMU_CONTEXT_SEGMENTS  (QEMU_CONTEXT_AMD64 | 0x0004)
#define QEMU_CONTEXT_FLOATING_POINT  (QEMU_CONTEXT_AMD64 | 0x0008)
#define QEMU_CONTEXT_DEBUG_REGISTERS (QEMU_CONTEXT_AMD64 | 0x0010)
#define QEMU_CONTEXT_FULL (QEMU_CONTEXT_CONTROL | QEMU_CONTEXT_INTEGER | QEMU_CONTEXT_FLOATING_POINT)
#define QEMU_CONTEXT_ALL (QEMU_CONTEXT_CONTROL | QEMU_CONTEXT_INTEGER | QEMU_CONTEXT_SEGMENTS | QEMU_CONTEXT_FLOATING_POINT | QEMU_CONTEXT_DEBUG_REGISTERS)

typedef struct DECLSPEC_ALIGN(16) qemu_M128A
{
    ULONGLONG Low;
    LONGLONG High;
} qemu_M128A, *Pqemu_M128A;

typedef struct _qemu_XMM_SAVE_AREA32
{
    WORD ControlWord;        /* 000 */
    WORD StatusWord;         /* 002 */
    BYTE TagWord;            /* 004 */
    BYTE Reserved1;          /* 005 */
    WORD ErrorOpcode;        /* 006 */
    DWORD ErrorOffset;       /* 008 */
    WORD ErrorSelector;      /* 00c */
    WORD Reserved2;          /* 00e */
    DWORD DataOffset;        /* 010 */
    WORD DataSelector;       /* 014 */
    WORD Reserved3;          /* 016 */
    DWORD MxCsr;             /* 018 */
    DWORD MxCsr_Mask;        /* 01c */
    qemu_M128A FloatRegisters[8]; /* 020 */
    qemu_M128A XmmRegisters[16];  /* 0a0 */
    BYTE Reserved4[96];      /* 1a0 */
} qemu_XMM_SAVE_AREA32, *Pqemu_XMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) {
    DWORD64 P1Home;          /* 000 */
    DWORD64 P2Home;          /* 008 */
    DWORD64 P3Home;          /* 010 */
    DWORD64 P4Home;          /* 018 */
    DWORD64 P5Home;          /* 020 */
    DWORD64 P6Home;          /* 028 */

    /* Control flags */
    DWORD ContextFlags;      /* 030 */
    DWORD MxCsr;             /* 034 */

    /* Segment */
    WORD SegCs;              /* 038 */
    WORD SegDs;              /* 03a */
    WORD SegEs;              /* 03c */
    WORD SegFs;              /* 03e */
    WORD SegGs;              /* 040 */
    WORD SegSs;              /* 042 */
    DWORD EFlags;            /* 044 */

    /* Debug */
    DWORD64 Dr0;             /* 048 */
    DWORD64 Dr1;             /* 050 */
    DWORD64 Dr2;             /* 058 */
    DWORD64 Dr3;             /* 060 */
    DWORD64 Dr6;             /* 068 */
    DWORD64 Dr7;             /* 070 */

    /* Integer */
    DWORD64 Rax;             /* 078 */
    DWORD64 Rcx;             /* 080 */
    DWORD64 Rdx;             /* 088 */
    DWORD64 Rbx;             /* 090 */
    DWORD64 Rsp;             /* 098 */
    DWORD64 Rbp;             /* 0a0 */
    DWORD64 Rsi;             /* 0a8 */
    DWORD64 Rdi;             /* 0b0 */
    DWORD64 R8;              /* 0b8 */
    DWORD64 R9;              /* 0c0 */
    DWORD64 R10;             /* 0c8 */
    DWORD64 R11;             /* 0d0 */
    DWORD64 R12;             /* 0d8 */
    DWORD64 R13;             /* 0e0 */
    DWORD64 R14;             /* 0e8 */
    DWORD64 R15;             /* 0f0 */

    /* Counter */
    DWORD64 Rip;             /* 0f8 */

    /* Floating point */
    union {
        qemu_XMM_SAVE_AREA32 FltSave;  /* 100 */
        struct {
            qemu_M128A Header[2];      /* 100 */
            qemu_M128A Legacy[8];      /* 120 */
            qemu_M128A Xmm0;           /* 1a0 */
            qemu_M128A Xmm1;           /* 1b0 */
            qemu_M128A Xmm2;           /* 1c0 */
            qemu_M128A Xmm3;           /* 1d0 */
            qemu_M128A Xmm4;           /* 1e0 */
            qemu_M128A Xmm5;           /* 1f0 */
            qemu_M128A Xmm6;           /* 200 */
            qemu_M128A Xmm7;           /* 210 */
            qemu_M128A Xmm8;           /* 220 */
            qemu_M128A Xmm9;           /* 230 */
            qemu_M128A Xmm10;          /* 240 */
            qemu_M128A Xmm11;          /* 250 */
            qemu_M128A Xmm12;          /* 260 */
            qemu_M128A Xmm13;          /* 270 */
            qemu_M128A Xmm14;          /* 280 */
            qemu_M128A Xmm15;          /* 290 */
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    /* Vector */
    qemu_M128A VectorRegister[26];     /* 300 */
    DWORD64 VectorControl;        /* 4a0 */

    /* Debug control */
    DWORD64 DebugControl;         /* 4a8 */
    DWORD64 LastBranchToRip;      /* 4b0 */
    DWORD64 LastBranchFromRip;    /* 4b8 */
    DWORD64 LastExceptionToRip;   /* 4c0 */
    DWORD64 LastExceptionFromRip; /* 4c8 */
} qemu_CONTEXT_X86_64;

extern uint64_t guest_exception_handler, guest_call_entry;
extern BOOL is_32_bit;

#endif /* QEMU_H */
