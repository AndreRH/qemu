/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu-version.h"

#include <wine/library.h>
#include <wine/debug.h>
#include <wine/unicode.h>
#include <delayloadhandler.h>

#include "qapi/error.h"
#include "qemu.h"
#include "qemu/path.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/help_option.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "exec/log.h"
#include "trace/control.h"
#include "glib-compat.h"

#include "pe.h"
#include "win_syscall.h"

char *exec_path;

int singlestep;
static const char *filename;
unsigned long guest_base;
int have_guest_base;
unsigned long reserved_va;
static struct qemu_pe_image image;
BOOL is_32_bit;

PEB guest_PEB;
PEB guest_PEB32;
static PEB_LDR_DATA guest_ldr;
static RTL_USER_PROCESS_PARAMETERS process_params;
static RTL_BITMAP guest_tls_bitmap;
static RTL_BITMAP guest_tls_expansion_bitmap;
static RTL_BITMAP guest_fls_bitmap;

__thread CPUState *thread_cpu;
__thread TEB *guest_teb;
__thread TEB32 *guest_teb32;

/* Helper function to read the TEB exception filter chain. */
uint64_t guest_exception_handler, guest_call_entry;

BOOL (WINAPI *pPathRemoveFileSpecA)(char *path);
BOOL (WINAPI *pPathRemoveFileSpecW)(WCHAR *path);

bool qemu_cpu_is_self(CPUState *cpu)
{
    qemu_log("qemu_cpu_is_self unimplemented.\n");
    return true;
}

void qemu_cpu_kick(CPUState *cpu)
{
    qemu_log("qemu_cpu_kick unimplemented.\n");
}

uint64_t cpu_get_tsc(CPUX86State *env)
{
    qemu_log("cpu_get_tsc unimplemented.\n");
    return 0;
}

int cpu_get_pic_interrupt(CPUX86State *env)
{
    qemu_log("cpu_get_pic_interrupt unimplemented.\n");
    return -1;
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
                     int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;
static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
    p[2] = tswap32(addr >> 32);
    p[3] = 0;
}
/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
}

static void free_teb(TEB *teb, TEB32 *teb32)
{
    VirtualFree(teb->Tib.StackLimit, 0, MEM_RELEASE);
    VirtualFree(teb, 0, MEM_RELEASE);
    if (teb32)
        VirtualFree(teb32, 0, MEM_RELEASE);
}

static TEB *alloc_teb(TEB32 **teb32)
{
    TEB *ret;
    TEB32 *ret32 = NULL;

    ret = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!ret)
    {
        fprintf(stderr, "Failed to allocate TEB\n");
        ExitProcess(1);
    }

    ret->Tib.Self = &ret->Tib;
    ret->Tib.ExceptionList = (void *)~0UL;
    ret->Peb = &guest_PEB;

    if (is_32_bit)
    {
        ret32 = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!ret)
        {
            fprintf(stderr, "Failed to allocate 32 bit TEB\n");
            ExitProcess(1);
        }

        ret32->Tib.Self = (qemu_ptr)(ULONG_PTR)&ret32->Tib;
        ret32->Tib.ExceptionList = ~0U;
        ret32->Peb = (qemu_ptr)(ULONG_PTR)&guest_PEB32;
    }

    *teb32 = ret32;
    return ret;
}

TEB *qemu_getTEB(void)
{
    return guest_teb;
}

static void init_thread_cpu(void)
{
    CPUX86State *env;
    void *stack;
    CPUState *cpu = thread_cpu;
    DWORD stack_reserve = image.stack_reserve ? image.stack_reserve : DEFAULT_STACK_SIZE;

    guest_teb = alloc_teb(&guest_teb32);

    if (!cpu)
        cpu = cpu_create(X86_CPU_TYPE_NAME("qemu64"));
    if (!cpu)
    {
        fprintf(stderr, "Unable to find CPU definition\n");
        ExitProcess(EXIT_FAILURE);
    }
    env = cpu->env_ptr;
    cpu_reset(cpu);

    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
    if (!is_32_bit)
    {
        /* enable 64 bit mode if possible */
        if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM))
        {
            fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
            ExitProcess(EXIT_FAILURE);
        }
        env->cr[4] |= CR4_PAE_MASK;
        env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
        env->hflags |= HF_LMA_MASK;
    }
    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* FPU control word. */
    cpu_set_fpuc(env, 0x27f);

    /* FIXME: I should RESERVE stack_reserve bytes, and commit only stack_commit bytes and
     * place a guard page at the end of the committed range. This will need exception handing
     * (and better knowledge in my brain), so commit the entire stack for now.
     *
     * Afaics when the reserved area is exhausted an exception is triggered and Windows does
     * not try to reserve more. Is this correct? */
    stack = VirtualAlloc(NULL, stack_reserve, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!stack)
    {
        fprintf(stderr, "Could not reserve stack space size %u.\n", stack_reserve);
        ExitProcess(EXIT_FAILURE);
    }
    /* Stack grows down, so point to the end of the allocation. */
    env->regs[R_ESP] = h2g(stack) + stack_reserve;

    env->idt.limit = is_32_bit ? 255 : 511;
    idt_table = my_alloc(sizeof(uint64_t) * (env->idt.limit + 1));
    env->idt.base = h2g(idt_table);
    set_idt(0, 0);
    set_idt(1, 0);
    set_idt(2, 0);
    set_idt(3, 3);
    set_idt(4, 3);
    set_idt(5, 0);
    set_idt(6, 0);
    set_idt(7, 0);
    set_idt(8, 0);
    set_idt(9, 0);
    set_idt(10, 0);
    set_idt(11, 0);
    set_idt(12, 0);
    set_idt(13, 0);
    set_idt(14, 0);
    set_idt(15, 0);
    set_idt(16, 0);
    set_idt(17, 0);
    set_idt(18, 0);
    set_idt(19, 0);
    set_idt(0x80, 3);

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = h2g(my_alloc(sizeof(uint64_t) * TARGET_GDT_ENTRIES));
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h(env->gdt.base);
        if (is_32_bit)
        {
            write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                    DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                    (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
        }
        else
        {
            /* 64 bit code segment */
            write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                    DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                    DESC_L_MASK |
                    (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
        }
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
    if (is_32_bit)
    {
        cpu_x86_load_seg(env, R_DS, __USER_DS);
        cpu_x86_load_seg(env, R_ES, __USER_DS);
        cpu_x86_load_seg(env, R_FS, __USER_DS);
        cpu_x86_load_seg(env, R_GS, __USER_DS);
        /* ??? */
        /* env->segs[R_FS].selector = 0; */
    }
    else
    {
        cpu_x86_load_seg(env, R_DS, 0);
        cpu_x86_load_seg(env, R_ES, 0);
        cpu_x86_load_seg(env, R_FS, 0);
        cpu_x86_load_seg(env, R_GS, 0);
    }
    env->segs[R_GS].base = h2g(guest_teb);

    guest_teb->Tib.StackBase = (void *)(h2g(stack) + stack_reserve);
    guest_teb->Tib.StackLimit = (void *)h2g(stack);

    if (guest_teb32)
    {
        env->segs[R_FS].base = h2g(guest_teb32);
        guest_teb32->Tib.StackBase = (qemu_ptr)(h2g(stack) + stack_reserve);
        guest_teb32->Tib.StackLimit = (qemu_ptr)h2g(stack);
    }

    qemu_loader_thread_init();

    /* FIXME: Figure out how to free the CPU, stack, TEB and IDT on thread exit. */
    thread_cpu = cpu;
}

static void cpu_env_to_context(CONTEXT_X86_64 *context, CPUX86State *env)
{
    X86XSaveArea buf;

    memset(context, 0, sizeof(*context));

    /* PXhome */

    context->ContextFlags = QEMU_CONTEXT_CONTROL | QEMU_CONTEXT_INTEGER | QEMU_CONTEXT_SEGMENTS | QEMU_CONTEXT_DEBUG_REGISTERS;
    context->MxCsr = env->mxcsr;

    /* FIXME: Do I really want .selector? I'm not entirely sure how those segment regs work. */
    context->SegCs = env->segs[R_CS].selector;
    context->SegDs = env->segs[R_DS].selector;
    context->SegEs = env->segs[R_ES].selector;
    context->SegFs = env->segs[R_FS].selector;
    context->SegGs = env->segs[R_GS].selector;
    context->SegSs = env->segs[R_SS].selector;

    context->EFlags = env->eflags;

    context->Dr0 = env->dr[0];
    context->Dr1 = env->dr[1];
    context->Dr2 = env->dr[2];
    context->Dr3 = env->dr[3];
    context->Dr6 = env->dr[6];
    context->Dr7 = env->dr[7];

    context->Rax = env->regs[R_EAX];
    context->Rbx = env->regs[R_EBX];
    context->Rcx = env->regs[R_ECX];
    context->Rdx = env->regs[R_EDX];
    context->Rsp = env->regs[R_ESP];
    context->Rbp = env->regs[R_EBP];
    context->Rsi = env->regs[R_ESI];
    context->Rdi = env->regs[R_EDI];
    context->R8 = env->regs[8];
    context->R9 = env->regs[9];
    context->R10 = env->regs[10];
    context->R11 = env->regs[11];
    context->R12 = env->regs[12];
    context->R13 = env->regs[13];
    context->R14 = env->regs[14];
    context->R15 = env->regs[15];
    context->Rip = env->eip;

    /* Floating point. */
    x86_cpu_xsave_all_areas(x86_env_get_cpu(env), &buf);
    memcpy(&context->FltSave, &buf.legacy, sizeof(context->FltSave));
    /* This is implicitly set to 0 by x86_cpu_xsave_all_areas (via memset),
     * but the fxsave implementation in target/i386/fpu_helper.c sets it
     * to the value below. */
    context->FltSave.MxCsr_Mask = 0x0000ffff;
}

static void cpu_loop(const void *code)
{
    CPUState *cs;
    CPUX86State *env;
    int trapnr;
    void *syscall;
    EXCEPTION_POINTERS except;
    EXCEPTION_RECORD exception_record;
    CONTEXT_X86_64 guest_context;

    cs = thread_cpu;
    env = cs->env_ptr;

    env->eip = h2g(code);

    for (;;)
    {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch (trapnr)
        {
            case EXCP_SYSCALL:
                syscall = g2h(env->regs[R_ECX]);
                if (!syscall) /* Return from guest to host. */
                    return;
                do_syscall(syscall);
                continue;

            case EXCP0E_PAGE:
                memset(&except, 0, sizeof(except));
                except.ExceptionRecord = &exception_record;
                except.ContextRecord = (void *)&guest_context;

                memset(&exception_record, 0, sizeof(exception_record));
                exception_record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
                exception_record.ExceptionFlags = 0;
                exception_record.ExceptionRecord = NULL;
                exception_record.ExceptionAddress = (void *)env->eip;
                exception_record.NumberParameters = 0;

                cpu_env_to_context(&guest_context, env);

                fprintf(stderr, "Got a page fault in user code, resuming execution at exception handler 0x%lx, rsp %p.\n",
                        guest_exception_handler, (void *)env->regs[R_ESP]);
                cpu_dump_state(cs, stderr, fprintf, 0);

                env->regs[R_ESP] -= 0x20; /* Reserve 32 bytes for the handler function. */
                /* It seems we have to deliberately misalign the stack by 8 bytes here because
                 * we don't push a return address onto the stack. */
                env->regs[R_ESP] &= ~0xf;
                env->regs[R_ESP] += 8;
                env->regs[R_ECX] = h2g(&except);
                env->eip = guest_exception_handler;
                continue;

            case EXCP_INTERRUPT:
                break;

            default:
                fprintf(stderr, "Unhandled trap %x, exiting.\n", trapnr);
                cpu_dump_state(cs, stderr, fprintf, 0);
                ExitProcess(255);
        }
    }
}

uint64_t qemu_execute(const void *code, uint64_t rcx)
{
    CPUState *cs;
    CPUX86State *env;
    uint64_t backup_eip, retval;
    target_ulong backup_regs[CPU_NB_REGS];
    static char *ret_code;

    if (!code)
    {
        fprintf(stderr, "Attempting to execute NULL.\n");
        ExitProcess(1);
    }

    if (!ret_code)
    {
        if (is_32_bit)
        {
            static const char ret_code32[] =
            {
                0x31, 0xc9,         /* xor %ecx, %ecx */
                0x0f, 0x05          /* syscall        */
            };
            ret_code = my_alloc(sizeof(ret_code32));
            memcpy(ret_code, ret_code32, sizeof(ret_code32));
        }
        else
        {
            static char ret_code64[] =
            {
                0x48, 0x31, 0xc9,   /* xor %rcx, %rcx */
                0x0f, 0x05          /* syscall        */
            };
            ret_code = ret_code64;
        }
    }

    /* The basic idea of this function is to back up all registers, write the function argument
     * into rcx, reserve stack space on the guest stack as the Win64 calling convention mandates
     * and call the emulated CPU to execute the requested code.
     *
     * We need to make sure the emulated CPU interrupts execution after the called function
     * returns and cpu_loop() returns as well. cpu_loop should not return if the function executes
     * a syscall. To achieve that, we push a return address into the guest stack that points to
     * an syscall(rcx=0) instruction. The this interrupt the CPU and cpu_loop recognizes the
     * zero value and returns gracefully.
     *
     * Afterwards restore registers and read the return value from EAX / RAX.
     *
     * Note that we're also storing caller-saved registers. From the view of our guest libraries
     * it is doing a syscall and not a function call, so it doesn't know it has to back up caller-
     * saved regs. We could alternatively tell gcc to clobber everything that is not callee-saved.
     * However, syscalls happen very often and callbacks into app code are relatively rare. Keep
     * the backup cost on the callback side. It's also a host memcpy vs emulated code. */
    cs = thread_cpu;
    if (!cs)
    {
        qemu_log("Initializing new CPU for thread %x.\n", GetCurrentThreadId());
        rcu_register_thread();
        init_thread_cpu();
        cs = thread_cpu;
        MODULE_DllThreadAttach(NULL);
    }
    env = cs->env_ptr;

    backup_eip = env->eip;
    memcpy(backup_regs, env->regs, sizeof(backup_regs));
    env->regs[R_ECX] = rcx;

    if (is_32_bit)
    {
        env->regs[R_ESP] -= 0x24; /* Keeps the longjmp detection simpler */
        /* Write the address of our return code onto the stack. */
        *(uint32_t *)g2h(env->regs[R_ESP]) = h2g(ret_code);
    }
    else
    {
        env->regs[R_ESP] -= 0x28; /* Reserve 32 bytes + 8 for the return address. */
        /* Write the address of our return code onto the stack. */
        *(uint64_t *)g2h(env->regs[R_ESP]) = h2g(ret_code);
    }

    qemu_log("Going to call guest code %p.\n", code);
    cpu_loop(code);

    if (backup_regs[R_ESP] - 0x20 != env->regs[R_ESP])
    {
        fprintf(stderr, "Stack pointer is 0x%lx, expected 0x%lx, longjump or unwind going on?\n",
                backup_regs[R_ESP] - 0x20, env->regs[R_ESP]);
        ExitProcess(1);
    }

    retval = env->regs[R_EAX];
    memcpy(env->regs, backup_regs, sizeof(backup_regs));
    env->eip = backup_eip;

    qemu_log("retval %lx.\n", retval);
    return retval;
}

static void usage(int exitcode);

static void handle_arg_help(const char *arg)
{
    usage(EXIT_SUCCESS);
}

static void handle_arg_log(const char *arg)
{
    int mask;

    mask = qemu_str_to_log_mask(arg);
    if (!mask)
    {
        qemu_print_log_usage(stdout);
        ExitProcess(EXIT_FAILURE);
    }
    qemu_log_needs_buffers();
    qemu_set_log(mask);
}

struct qemu_argument
{
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] =
{
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"help",       "",                 false, handle_arg_help,
     "",           ""},
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(int exitcode)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++)
    {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg)
        {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen)
        {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen)
        {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++)
    {
        if (arginfo->has_arg)
        {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        }
        else
        {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    ExitProcess(exitcode);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }
        /* Treat --foo the same as -foo.  */
        if (r[0] == '-') {
            r++;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        (void) fprintf(stderr,
                            "qemu: missing argument for option '%s'\n", r);
                        ExitProcess(EXIT_FAILURE);
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            (void) fprintf(stderr, "qemu: unknown option '%s'\n", r);
            ExitProcess(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        (void) fprintf(stderr, "qemu: no user program specified\n");
        ExitProcess(EXIT_FAILURE);
    }

    filename = argv[optind];
    exec_path = argv[optind];

    return optind;
}

static BOOL build_command_line(char **argv)
{
    int len;
    char **arg;
    LPWSTR p;
    RTL_USER_PROCESS_PARAMETERS* rupp = &process_params;

    if (rupp->CommandLine.Buffer) return TRUE; /* already got it from the server */

    len = 0;
    for (arg = argv; *arg; arg++)
    {
        BOOL has_space;
        int bcount;
        char* a;

        has_space=FALSE;
        bcount=0;
        a=*arg;
        if( !*a ) has_space=TRUE;
        while (*a!='\0') {
            if (*a=='\\') {
                bcount++;
            } else {
                if (*a==' ' || *a=='\t') {
                    has_space=TRUE;
                } else if (*a=='"') {
                    /* doubling of '\' preceding a '"',
                     * plus escaping of said '"'
                     */
                    len+=2*bcount+1;
                }
                bcount=0;
            }
            a++;
        }
        len+=(a-*arg)+1 /* for the separating space */;
        if (has_space)
            len+=2+bcount; /* for the quotes and doubling of '\' preceding the closing quote */
    }

    if (!(rupp->CommandLine.Buffer = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR))))
        return FALSE;

    p = rupp->CommandLine.Buffer;
    rupp->CommandLine.Length = (len - 1) * sizeof(WCHAR);
    rupp->CommandLine.MaximumLength = len * sizeof(WCHAR);
    for (arg = argv; *arg; arg++)
    {
        BOOL has_space,has_quote;
        WCHAR* a, *argW;
        int bcount;

        bcount = MultiByteToWideChar(CP_ACP, 0, *arg, -1, NULL, 0);
        argW = my_alloc(bcount * sizeof(*argW));
        MultiByteToWideChar(CP_ACP, 0, *arg, -1, argW, bcount);

        /* Check for quotes and spaces in this argument */
        has_space=has_quote=FALSE;
        a=argW;
        if( !*a ) has_space=TRUE;
        while (*a!='\0') {
            if (*a==' ' || *a=='\t') {
                has_space=TRUE;
                if (has_quote)
                    break;
            } else if (*a=='"') {
                has_quote=TRUE;
                if (has_space)
                    break;
            }
            a++;
        }

        /* Now transfer it to the command line */
        if (has_space)
            *p++='"';
        if (has_quote || has_space) {
            bcount=0;
            a=argW;
            while (*a!='\0') {
                if (*a=='\\') {
                    *p++=*a;
                    bcount++;
                } else {
                    if (*a=='"') {
                        int i;

                        /* Double all the '\\' preceding this '"', plus one */
                        for (i=0;i<=bcount;i++)
                            *p++='\\';
                        *p++='"';
                    } else {
                        *p++=*a;
                    }
                    bcount=0;
                }
                a++;
            }
        } else {
            WCHAR* x = argW;
            while ((*p=*x++)) p++;
        }
        if (has_space) {
            int i;

            /* Double all the '\' preceding the closing quote */
            for (i=0;i<bcount;i++)
                *p++='\\';
            *p++='"';
        }
        *p++=' ';
        my_free(argW);
    }
    if (p > rupp->CommandLine.Buffer)
        p--;  /* remove last space */
    *p = '\0';

    return TRUE;
}

static void init_process_params(char **argv, const char *filenme)
{
    WCHAR *cwd;
    DWORD size;
    static const WCHAR qemu_x86_64exeW[] = {'q','e','m','u','-','x','8','6','_','6','4','.','e','x','e', 0};

    /* FIXME: Wine allocates the string buffer right behind the process parameter structure. */
    build_command_line(argv);
    guest_PEB.ProcessParameters = &process_params;
    guest_PEB.LdrData = &guest_ldr;

    /* FIXME: If no explicit title is given WindowTitle and ImagePathName are the same, except
     * that WindowTitle has the .so ending removed. This could be used for a more reliable check.
     *
     * Is there a way to catch a case where the title is deliberately set to "qemu-x86_64.exe"? */
    if (strstrW(NtCurrentTeb()->Peb->ProcessParameters->WindowTitle.Buffer, qemu_x86_64exeW))
    {
        RtlCreateUnicodeStringFromAsciiz(&guest_PEB.ProcessParameters->WindowTitle, filename);
    }
    else
    {
        guest_PEB.ProcessParameters->WindowTitle = NtCurrentTeb()->Peb->ProcessParameters->WindowTitle;
    }

    /* The effect of this code is to inject the current working directory into the top of the DLL search
     * path. It will later be replaced by the directory where the .exe was loaded from. The \\qemu-x86_64.exe.so
     * part will be cut off by the loader. */
    size = GetCurrentDirectoryW(0, NULL);
    cwd = my_alloc((size + 16) * sizeof(*cwd));
    GetCurrentDirectoryW(size, cwd);
    cwd[size - 1] = '\\';
    cwd[size] = 0;
    strcatW(cwd, qemu_x86_64exeW);
    RtlInitUnicodeString(&guest_PEB.ProcessParameters->ImagePathName, cwd);

    guest_ldr.Length = sizeof(guest_ldr);
    guest_ldr.Initialized = TRUE;
    RtlInitializeBitMap( &guest_tls_bitmap, guest_PEB.TlsBitmapBits, sizeof(guest_PEB.TlsBitmapBits) * 8 );
    RtlInitializeBitMap( &guest_tls_expansion_bitmap, guest_PEB.TlsExpansionBitmapBits,
                         sizeof(guest_PEB.TlsExpansionBitmapBits) * 8 );
    RtlInitializeBitMap( &guest_fls_bitmap, guest_PEB.FlsBitmapBits, sizeof(guest_PEB.FlsBitmapBits) * 8 );
    RtlSetBits( guest_PEB.TlsBitmap, 0, 1 ); /* TLS index 0 is reserved and should be initialized to NULL. */
    RtlSetBits( guest_PEB.FlsBitmap, 0, 1 );
    InitializeListHead( &guest_PEB.FlsListHead );
    InitializeListHead( &guest_ldr.InLoadOrderModuleList );
    InitializeListHead( &guest_ldr.InMemoryOrderModuleList );
    InitializeListHead( &guest_ldr.InInitializationOrderModuleList );

    guest_PEB.ProcessParameters->CurrentDirectory = NtCurrentTeb()->Peb->ProcessParameters->CurrentDirectory;
}

/* After blocking the 64 bit address space the host stack has no room to grow. Reserve some
 * space now. */
static void growstack(void)
{
    volatile char blob[1048576*4];
    memset((char *)blob, 0xad, sizeof(blob));
}

static void block_address_space(void)
{
    void *map;
    unsigned long size = 1UL << 63UL;

    /* mmap as much as possible. */
    while(size >= 4096)
    {
        do
        {
            map = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
        } while(map != (void *)0xffffffffffffffff);
        size >>= 1;
    }

    /* It appears that the heap manager has a few pages we can't mmap, but malloc will successfully
     * allocate from. On my system this gives me about 140kb of memory. */
    size = 1UL << 63UL;
    while(size)
    {
        do
        {
            map = malloc(size);
        } while(map);
        size >>= 1;
    }

    /* Same for Wine's heap. */
    size = 1UL << 63UL;
    while(size)
    {
        do
        {
            map = my_alloc(size);
        } while(map);
        size >>= 1;
    }
}

int main(int argc, char **argv, char **envp)
{
    HMODULE exe_module, shlwapi_module;
    int optind, i;
    WCHAR *filenameW;
    int ret;
    void *low2gb = NULL, *low4gb = NULL;
    unsigned long min_addr;
    FILE *min_file = fopen("/proc/sys/vm/mmap_min_addr", "r");
    void **osx_ptrs = wine_mmap_get_qemu_ptrs();

    /* FIXME: The order of operations is a mess, especially setting up the TEB and loading the
     * guest binary. */

    /* Try to block the low 4 GB. We will free it later. If we're running a 32 bit program, we
     * will block the entire address space before freeing the low 4 GB to force allocations into
     * a 32 bit address space. */
    if (osx_ptrs && osx_ptrs[0])
    {
        low2gb = osx_ptrs[1];
        low4gb = osx_ptrs[2];
    }
    else if (min_file && fscanf(min_file, "%lu", &min_addr) == 1)
    {
        low2gb = mmap((void *)min_addr, 0x80000000 - min_addr, PROT_NONE,
                MAP_FIXED | MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
        low4gb = mmap((void *)0x80000000, 0x80000000, PROT_NONE,
                MAP_FIXED | MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    }
    else
    {
        fprintf(stderr, "Cannot read mmap_min_addr, 32 bit programs will fail.\n");
    }

    if (min_file)
        fclose(min_file);

    parallel_cpus = true;

    optind = parse_args(argc, argv);
    /* This is kinda dirty. It is too late to have an effect on kernel32 initialization,
     * but it should work OK for msvcrt because qemu doesn't link against msvcrt and the
     * library is not yet loaded. Turns out this is exactly what we want, but that's
     * more of a lucky coincidence than by design.
     *
     * It would be a bit more reliable if we added the offset before returning it to the
     * app, but msvcrt's getmainargs() has an option to expand wildcards, which makes
     * everything unpredictable. */
    __wine_main_argc -= optind;
    __wine_main_argv += optind;
    __wine_main_wargv += optind;

    i = MultiByteToWideChar(CP_ACP, 0, filename, -1, NULL, 0);
    filenameW = my_alloc(i * sizeof(*filenameW));
    MultiByteToWideChar(CP_ACP, 0, filename, -1, filenameW, i);

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    shlwapi_module = LoadLibraryA("shlwapi.dll");
    if (!shlwapi_module)
    {
        fprintf(stderr, "Cannot load shlwapi.dll\n");
        ExitProcess(1);
    }
    pPathRemoveFileSpecA = (void *)GetProcAddress(shlwapi_module, "PathRemoveFileSpecA");
    if (!pPathRemoveFileSpecA)
    {
        fprintf(stderr, "PathRemoveFileSpecA not found in shlwapi.dll\n");
        ExitProcess(1);
    }
    pPathRemoveFileSpecW = (void *)GetProcAddress(shlwapi_module, "PathRemoveFileSpecW");
    if (!pPathRemoveFileSpecW)
    {
        fprintf(stderr, "PathRemoveFileSpecW not found in shlwapi.dll\n");
        ExitProcess(1);
    }

    tcg_exec_init(0);
    tcg_prologue_init(tcg_ctx);
    init_thread_cpu();

    init_process_params(argv + optind, filename);

    is_32_bit = qemu_is_32_bit_exe(filenameW);

    if (!load_host_dlls(FALSE))
    {
        fprintf(stderr, "Failed to load host DLLs\n");
        ExitProcess(EXIT_FAILURE);
    }

    fprintf(stderr, "Lib load done, doing address space dance\n");
    Sleep(100000);
    if (is_32_bit)
    {
        RemoveEntryList( &guest_teb->TlsLinks );
        free_teb(guest_teb, guest_teb32);
        memset(&guest_PEB, 0, sizeof(guest_PEB));
        my_free(process_params.CommandLine.Buffer);
        memset(&process_params, 0, sizeof(process_params));

        if (!low2gb || !low4gb)
        {
            fprintf(stderr, "Failed to reserve low 4 GB, cannot set up address space for Win32.\n");
            ExitProcess(EXIT_FAILURE);
        }
        growstack();
        block_address_space();
    }

    /* FIXME: OSX has the pesky attitude to load its libraries at the place where we want to
     * put our executables. Prevent this by only freeing 2-4GB now, and 0-2GB after loading
     * msvcrt. This will break apps that aren't large address aware though. */
    if (low4gb)
        munmap(low4gb, 0x80000000); /* FIXME: Only if large address aware. */

    if (is_32_bit)
    {
        /* Re-init the CPU with (hopefully) 32 bit pointers. */

        /* Need a heap handle < 2^32. Hopefully we don't free old allocs :-) */
        NtCurrentTeb()->Peb->ProcessHeap = HeapCreate(HEAP_GROWABLE, 0, 0);

        init_process_params(argv + optind, filename);
        init_thread_cpu();
        fprintf(stderr, "32 bit environment set up\n");
    }

    if (!load_host_dlls(TRUE))
    {
        fprintf(stderr, "Failed to load host DLLs\n");
        ExitProcess(EXIT_FAILURE);
    }

    if (low2gb)
        munmap(low2gb, 0x80000000 - (ULONG_PTR)low2gb);
    if (osx_ptrs && osx_ptrs[0])
        munmap(osx_ptrs[0], 0x100000 - (ULONG_PTR)osx_ptrs[0]);

    exe_module = qemu_LoadLibrary(filenameW, 0);
    my_free(filenameW);
    if (!exe_module)
    {
        fprintf(stderr, "Failed to load \"%s\", last error %u.\n", filename, GetLastError());
        ExitProcess(EXIT_FAILURE);
    }
    qemu_get_image_info(exe_module, &image);
    guest_PEB.ImageBaseAddress = exe_module;

    if (image.stack_reserve != DEFAULT_STACK_SIZE)
    {
        void *stack;
        CPUX86State *env = thread_cpu->env_ptr;

        VirtualFree(guest_teb->Tib.StackLimit, 0, MEM_RELEASE);
        stack = VirtualAlloc(NULL, image.stack_reserve, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!stack)
        {
            fprintf(stderr, "Could not reserve stack space size %u.\n", image.stack_reserve);
            ExitProcess(EXIT_FAILURE);
        }

        /* Stack grows down, so point to the end of the allocation. */
        env->regs[R_ESP] = h2g(stack) + image.stack_reserve;
        guest_teb->Tib.StackBase = (void *)(h2g(stack) + image.stack_reserve);
        guest_teb->Tib.StackLimit = (void *)h2g(stack);
        if (guest_teb32)
        {
            guest_teb32->Tib.StackBase = (qemu_ptr)(h2g(stack) + image.stack_reserve);
            guest_teb32->Tib.StackLimit = (qemu_ptr)h2g(stack);
        }
    }

    signal_init();

    qemu_log("CPU Setup done\n");

    if (qemu_LdrInitializeThunk())
    {
        fprintf(stderr, "Process initialization failed.\n");
        ExitProcess(EXIT_FAILURE);
    }
    qemu_log("Process init done.\n");

    /* Should not return, guest_call_entry calls ExitProcess if need be. */
    ret = qemu_execute(QEMU_G2H(guest_call_entry), QEMU_H2G(image.entrypoint));

    fprintf(stderr, "Main function returned, result %u.\n", ret);
    return ret;
}

BOOL qemu_DllMain(DWORD reason, void *reserved)
{
    qemu_log("qemu DllMain(%u).\n", reason);

    if (reason == DLL_THREAD_DETACH && thread_cpu)
    {
        qemu_log("Informing rcu about disappearing thread.\n");
        rcu_unregister_thread();
    }

    return TRUE;
}
