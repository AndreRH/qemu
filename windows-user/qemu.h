#ifndef QEMU_H
#define QEMU_H

#include <asm-generic/int-ll64.h>
#include <windows.h>

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
    qemu_log("lock_user\n");
    return g2h(guest_addr);
}

static inline void unlock_user(void *host_ptr, abi_ulong guest_addr,
                               long len)
{
    qemu_log("unlock_user\n");
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

static inline void *my_alloc(size_t s)
{
    return HeapAlloc(GetProcessHeap(), 0, s);
}

static inline void my_free(void *p)
{
    HeapFree(GetProcessHeap(), 0, p);
}

#endif /* QEMU_H */
