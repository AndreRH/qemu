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

#include <windows.h>

#include "pe.h"

char *exec_path;

int singlestep;
static const char *filename;
unsigned long mmap_min_addr;
unsigned long guest_base;
int have_guest_base;
unsigned long reserved_va;

static inline void *my_alloc(size_t s)
{
    return HeapAlloc(GetProcessHeap(), 0, s);
}

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

static void cpu_loop(CPUX86State *env)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int trapnr;

    for (;;)
    {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);

        qemu_log("Got trap nr %x, syscall %x\n", trapnr, EXCP_SYSCALL);
        cpu_dump_state(cs, stderr, fprintf, 0);
        break;
    }
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

int main(int argc, char **argv, char **envp)
{
    CPUX86State *env;
    CPUState *cpu;
    HMODULE exe_module;
    struct qemu_pe_image image;
    void *stack;

    parse_args(argc, argv);

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    exe_module = qemu_LoadLibraryA(filename);
    if (!exe_module)
    {
        fprintf(stderr, "Failed to load \"%s\", last error %u.\n", filename, GetLastError());
        ExitProcess(EXIT_FAILURE);
    }
    qemu_get_image_info(exe_module, &image);

    tcg_exec_init(0);
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
    /* enable 64 bit mode if possible */
    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM))
    {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        ExitProcess(EXIT_FAILURE);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    tcg_prologue_init(tcg_ctx);

    env->eip = h2g(image.entrypoint);

    /* FIXME: I should RESERVE stack_reserve bytes, and commit only stack_commit bytes and
     * place a guard page at the end of the committed range. This will need exception handing
     * (and better knowledge in my brain), so commit the entire stack for now.
     *
     * Afaics when the reserved area is exhausted an exception is triggered and Windows does
     * not try to reserve more. Is this correct? */
    stack = VirtualAlloc(NULL, image.stack_reserve, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!stack)
    {
        fprintf(stderr, "Could not reserve stack space.\n");
        ExitProcess(EXIT_FAILURE);
    }
    /* Stack grows down, so point to the end of the allocation. */
    env->regs[R_ESP] = h2g(stack) + image.stack_reserve;

    env->idt.limit = 255;
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
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 DESC_L_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);

    qemu_log("CPU Setup done\n");
    cpu_dump_state(cpu, stderr, fprintf, 0);

    cpu_loop(env);

    return 0;
}
