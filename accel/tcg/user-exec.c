/*
 *  User emulator execution
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/bitops.h"
#include "exec/cpu_ldst.h"
#include "translate-all.h"
#include "exec/helper-proto.h"
#include "qemu/atomic128.h"

#undef EAX
#undef ECX
#undef EDX
#undef EBX
#undef ESP
#undef EBP
#undef ESI
#undef EDI
#undef EIP
#ifdef __linux__
#endif

__thread uintptr_t helper_retaddr;

#if defined(__i386__)

#if defined(__NetBSD__)
#include <ucontext.h>

#define EIP_sig(context)     ((context)->uc_mcontext.__gregs[_REG_EIP])
#define TRAP_sig(context)    ((context)->uc_mcontext.__gregs[_REG_TRAPNO])
#define ERROR_sig(context)   ((context)->uc_mcontext.__gregs[_REG_ERR])
#define MASK_sig(context)    ((context)->uc_sigmask)
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <ucontext.h>

#define EIP_sig(context)  (*((unsigned long *)&(context)->uc_mcontext.mc_eip))
#define TRAP_sig(context)    ((context)->uc_mcontext.mc_trapno)
#define ERROR_sig(context)   ((context)->uc_mcontext.mc_err)
#define MASK_sig(context)    ((context)->uc_sigmask)
#elif defined(__OpenBSD__)
#define EIP_sig(context)     ((context)->sc_eip)
#define TRAP_sig(context)    ((context)->sc_trapno)
#define ERROR_sig(context)   ((context)->sc_err)
#define MASK_sig(context)    ((context)->sc_mask)
#else
#define EIP_sig(context)     ((context)->uc_mcontext.gregs[REG_EIP])
#define TRAP_sig(context)    ((context)->uc_mcontext.gregs[REG_TRAPNO])
#define ERROR_sig(context)   ((context)->uc_mcontext.gregs[REG_ERR])
#define MASK_sig(context)    ((context)->uc_sigmask)
#endif

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    return -1;
}

#elif defined(__x86_64__)

#ifdef __NetBSD__
#define PC_sig(context)       _UC_MACHINE_PC(context)
#define TRAP_sig(context)     ((context)->uc_mcontext.__gregs[_REG_TRAPNO])
#define ERROR_sig(context)    ((context)->uc_mcontext.__gregs[_REG_ERR])
#define MASK_sig(context)     ((context)->uc_sigmask)
#elif defined(__OpenBSD__)
#define PC_sig(context)       ((context)->sc_rip)
#define TRAP_sig(context)     ((context)->sc_trapno)
#define ERROR_sig(context)    ((context)->sc_err)
#define MASK_sig(context)     ((context)->sc_mask)
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <ucontext.h>

#define PC_sig(context)  (*((unsigned long *)&(context)->uc_mcontext.mc_rip))
#define TRAP_sig(context)     ((context)->uc_mcontext.mc_trapno)
#define ERROR_sig(context)    ((context)->uc_mcontext.mc_err)
#define MASK_sig(context)     ((context)->uc_sigmask)
#else
#define PC_sig(context)       ((context)->uc_mcontext.gregs[REG_RIP])
#define TRAP_sig(context)     ((context)->uc_mcontext.gregs[REG_TRAPNO])
#define ERROR_sig(context)    ((context)->uc_mcontext.gregs[REG_ERR])
#define MASK_sig(context)     ((context)->uc_sigmask)
#endif

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    return -1;
}

#elif defined(_ARCH_PPC)

/***********************************************************************
 * signal context platform-specific definitions
 * From Wine
 */
#ifdef linux
/* All Registers access - only for local access */
#define REG_sig(reg_name, context)              \
    ((context)->uc_mcontext.regs->reg_name)
/* Gpr Registers access  */
#define GPR_sig(reg_num, context)              REG_sig(gpr[reg_num], context)
/* Program counter */
#define IAR_sig(context)                       REG_sig(nip, context)
/* Machine State Register (Supervisor) */
#define MSR_sig(context)                       REG_sig(msr, context)
/* Count register */
#define CTR_sig(context)                       REG_sig(ctr, context)
/* User's integer exception register */
#define XER_sig(context)                       REG_sig(xer, context)
/* Link register */
#define LR_sig(context)                        REG_sig(link, context)
/* Condition register */
#define CR_sig(context)                        REG_sig(ccr, context)

/* Float Registers access  */
#define FLOAT_sig(reg_num, context)                                     \
    (((double *)((char *)((context)->uc_mcontext.regs + 48 * 4)))[reg_num])
#define FPSCR_sig(context) \
    (*(int *)((char *)((context)->uc_mcontext.regs + (48 + 32 * 2) * 4)))
/* Exception Registers access */
#define DAR_sig(context)                       REG_sig(dar, context)
#define DSISR_sig(context)                     REG_sig(dsisr, context)
#define TRAP_sig(context)                      REG_sig(trap, context)
#endif /* linux */

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#include <ucontext.h>
#define IAR_sig(context)               ((context)->uc_mcontext.mc_srr0)
#define MSR_sig(context)               ((context)->uc_mcontext.mc_srr1)
#define CTR_sig(context)               ((context)->uc_mcontext.mc_ctr)
#define XER_sig(context)               ((context)->uc_mcontext.mc_xer)
#define LR_sig(context)                ((context)->uc_mcontext.mc_lr)
#define CR_sig(context)                ((context)->uc_mcontext.mc_cr)
/* Exception Registers access */
#define DAR_sig(context)               ((context)->uc_mcontext.mc_dar)
#define DSISR_sig(context)             ((context)->uc_mcontext.mc_dsisr)
#define TRAP_sig(context)              ((context)->uc_mcontext.mc_exc)
#endif /* __FreeBSD__|| __FreeBSD_kernel__ */

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    ucontext_t *uc = puc;
#else
    ucontext_t *uc = puc;
#endif
    unsigned long pc;
    int is_write;

    pc = IAR_sig(uc);
    is_write = 0;
#if 0
    /* ppc 4xx case */
    if (DSISR_sig(uc) & 0x00800000) {
        is_write = 1;
    }
#else
    if (TRAP_sig(uc) != 0x400 && (DSISR_sig(uc) & 0x02000000)) {
        is_write = 1;
    }
#endif
    return handle_cpu_signal(pc, info, is_write, &uc->uc_sigmask);
}

#elif defined(__alpha__)

int cpu_signal_handler(int host_signum, void *pinfo,
                           void *puc)
{
    siginfo_t *info = pinfo;
    ucontext_t *uc = puc;
    uint32_t *pc = uc->uc_mcontext.sc_pc;
    uint32_t insn = *pc;
    int is_write = 0;

    /* XXX: need kernel patch to get write flag faster */
    switch (insn >> 26) {
    case 0x0d: /* stw */
    case 0x0e: /* stb */
    case 0x0f: /* stq_u */
    case 0x24: /* stf */
    case 0x25: /* stg */
    case 0x26: /* sts */
    case 0x27: /* stt */
    case 0x2c: /* stl */
    case 0x2d: /* stq */
    case 0x2e: /* stl_c */
    case 0x2f: /* stq_c */
        is_write = 1;
    }

    return handle_cpu_signal(pc, info, is_write, &uc->uc_sigmask);
}
#elif defined(__sparc__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    int is_write;
    uint32_t insn;
#if !defined(__arch64__) || defined(CONFIG_SOLARIS)
    uint32_t *regs = (uint32_t *)(info + 1);
    void *sigmask = (regs + 20);
    /* XXX: is there a standard glibc define ? */
    unsigned long pc = regs[1];
#else
#ifdef __linux__
    struct sigcontext *sc = puc;
    unsigned long pc = sc->sigc_regs.tpc;
    void *sigmask = (void *)sc->sigc_mask;
#elif defined(__OpenBSD__)
    struct sigcontext *uc = puc;
    unsigned long pc = uc->sc_pc;
    void *sigmask = (void *)(long)uc->sc_mask;
#elif defined(__NetBSD__)
    ucontext_t *uc = puc;
    unsigned long pc = _UC_MACHINE_PC(uc);
    void *sigmask = (void *)&uc->uc_sigmask;
#endif
#endif

    /* XXX: need kernel patch to get write flag faster */
    is_write = 0;
    insn = *(uint32_t *)pc;
    if ((insn >> 30) == 3) {
        switch ((insn >> 19) & 0x3f) {
        case 0x05: /* stb */
        case 0x15: /* stba */
        case 0x06: /* sth */
        case 0x16: /* stha */
        case 0x04: /* st */
        case 0x14: /* sta */
        case 0x07: /* std */
        case 0x17: /* stda */
        case 0x0e: /* stx */
        case 0x1e: /* stxa */
        case 0x24: /* stf */
        case 0x34: /* stfa */
        case 0x27: /* stdf */
        case 0x37: /* stdfa */
        case 0x26: /* stqf */
        case 0x36: /* stqfa */
        case 0x25: /* stfsr */
        case 0x3c: /* casa */
        case 0x3e: /* casxa */
            is_write = 1;
            break;
        }
    }
    return handle_cpu_signal(pc, info, is_write, sigmask);
}

#elif defined(__arm__)

#if defined(__NetBSD__)
#include <ucontext.h>
#endif

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
#if defined(__NetBSD__)
    ucontext_t *uc = puc;
#else
    ucontext_t *uc = puc;
#endif
    unsigned long pc;
    int is_write;

#if defined(__NetBSD__)
    pc = uc->uc_mcontext.__gregs[_REG_R15];
#elif defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ <= 3))
    pc = uc->uc_mcontext.gregs[R15];
#else
    pc = uc->uc_mcontext.arm_pc;
#endif

    /* error_code is the FSR value, in which bit 11 is WnR (assuming a v6 or
     * later processor; on v5 we will always report this as a read).
     */
    is_write = extract32(uc->uc_mcontext.error_code, 11, 1);
    return handle_cpu_signal(pc, info, is_write, &uc->uc_sigmask);
}

#elif defined(__aarch64__)

int cpu_signal_handler(int host_signum, void *pinfo, void *puc)
{
    return -1;
}

#elif defined(__s390__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    ucontext_t *uc = puc;
    unsigned long pc;
    uint16_t *pinsn;
    int is_write = 0;

    pc = uc->uc_mcontext.psw.addr;

    /* ??? On linux, the non-rt signal handler has 4 (!) arguments instead
       of the normal 2 arguments.  The 3rd argument contains the "int_code"
       from the hardware which does in fact contain the is_write value.
       The rt signal handler, as far as I can tell, does not give this value
       at all.  Not that we could get to it from here even if it were.  */
    /* ??? This is not even close to complete, since it ignores all
       of the read-modify-write instructions.  */
    pinsn = (uint16_t *)pc;
    switch (pinsn[0] >> 8) {
    case 0x50: /* ST */
    case 0x42: /* STC */
    case 0x40: /* STH */
        is_write = 1;
        break;
    case 0xc4: /* RIL format insns */
        switch (pinsn[0] & 0xf) {
        case 0xf: /* STRL */
        case 0xb: /* STGRL */
        case 0x7: /* STHRL */
            is_write = 1;
        }
        break;
    case 0xe3: /* RXY format insns */
        switch (pinsn[2] & 0xff) {
        case 0x50: /* STY */
        case 0x24: /* STG */
        case 0x72: /* STCY */
        case 0x70: /* STHY */
        case 0x8e: /* STPQ */
        case 0x3f: /* STRVH */
        case 0x3e: /* STRV */
        case 0x2f: /* STRVG */
            is_write = 1;
        }
        break;
    }
    return handle_cpu_signal(pc, info, is_write, &uc->uc_sigmask);
}

#elif defined(__mips__)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    ucontext_t *uc = puc;
    greg_t pc = uc->uc_mcontext.pc;
    int is_write;

    /* XXX: compute is_write */
    is_write = 0;
    return handle_cpu_signal(pc, info, is_write, &uc->uc_sigmask);
}

#elif defined(__riscv)

int cpu_signal_handler(int host_signum, void *pinfo,
                       void *puc)
{
    siginfo_t *info = pinfo;
    ucontext_t *uc = puc;
    greg_t pc = uc->uc_mcontext.__gregs[REG_PC];
    uint32_t insn = *(uint32_t *)pc;
    int is_write = 0;

    /* Detect store by reading the instruction at the program
       counter. Note: we currently only generate 32-bit
       instructions so we thus only detect 32-bit stores */
    switch (((insn >> 0) & 0b11)) {
    case 3:
        switch (((insn >> 2) & 0b11111)) {
        case 8:
            switch (((insn >> 12) & 0b111)) {
            case 0: /* sb */
            case 1: /* sh */
            case 2: /* sw */
            case 3: /* sd */
            case 4: /* sq */
                is_write = 1;
                break;
            default:
                break;
            }
            break;
        case 9:
            switch (((insn >> 12) & 0b111)) {
            case 2: /* fsw */
            case 3: /* fsd */
            case 4: /* fsq */
                is_write = 1;
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
    }

    /* Check for compressed instructions */
    switch (((insn >> 13) & 0b111)) {
    case 7:
        switch (insn & 0b11) {
        case 0: /*c.sd */
        case 2: /* c.sdsp */
            is_write = 1;
            break;
        default:
            break;
        }
        break;
    case 6:
        switch (insn & 0b11) {
        case 0: /* c.sw */
        case 3: /* c.swsp */
            is_write = 1;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return handle_cpu_signal(pc, info, is_write, &uc->uc_sigmask);
}

#else

#error host CPU specific signal handler needed

#endif

/* The softmmu versions of these helpers are in cputlb.c.  */

/* Do not allow unaligned operations to proceed.  Return the host address.  */
static void *atomic_mmu_lookup(CPUArchState *env, target_ulong addr,
                               int size, uintptr_t retaddr)
{
    /* Enforce qemu required alignment.  */
    if (unlikely(addr & (size - 1))) {
        cpu_loop_exit_atomic(ENV_GET_CPU(env), retaddr);
    }
    helper_retaddr = retaddr;
    return g2h(addr);
}

/* Macro to call the above, with local variables from the use context.  */
#define ATOMIC_MMU_DECLS do {} while (0)
#define ATOMIC_MMU_LOOKUP  atomic_mmu_lookup(env, addr, DATA_SIZE, GETPC())
#define ATOMIC_MMU_CLEANUP do { helper_retaddr = 0; } while (0)

#define ATOMIC_NAME(X)   HELPER(glue(glue(atomic_ ## X, SUFFIX), END))
#define EXTRA_ARGS

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

/* The following is only callable from other helpers, and matches up
   with the softmmu version.  */

#if HAVE_ATOMIC128 || HAVE_CMPXCHG128

#undef EXTRA_ARGS
#undef ATOMIC_NAME
#undef ATOMIC_MMU_LOOKUP

#define EXTRA_ARGS     , TCGMemOpIdx oi, uintptr_t retaddr
#define ATOMIC_NAME(X) \
    HELPER(glue(glue(glue(atomic_ ## X, SUFFIX), END), _mmu))
#define ATOMIC_MMU_LOOKUP  atomic_mmu_lookup(env, addr, DATA_SIZE, retaddr)

#define DATA_SIZE 16
#include "atomic_template.h"
#endif
