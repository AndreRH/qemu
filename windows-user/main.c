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
#include "elf.h"
#include "exec/log.h"
#include "trace/control.h"
#include "glib-compat.h"

#include <windows.h>

char *exec_path;

int singlestep;
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

static void enable_log(void)
{
    qemu_log_needs_buffers();
    qemu_set_log(0xffffffff);
}

static const char testcode[] =
{
    0x48, 0xc7, 0xc0, 0x7b, 0x00, 0x00, 0x00,   /* mov    $0x7b,%rax    */
    0x48, 0xc7, 0xc3, 0xc8, 0x01, 0x00, 0x00,   /* mov    $0x1c8,%rbx   */
    0x48, 0xc7, 0xc1, 0x15, 0x03, 0x00, 0x00,   /* mov    $0x315,%rcx   */
    0x48, 0xf7, 0xe3,                           /* mul    %rbx          */
    0x0f, 0x05,                                 /* syscall              */
};

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

int main(int argc, char **argv, char **envp)
{
    CPUX86State *env;
    CPUState *cpu;

    enable_log();
    qemu_log("Hello qemu user\n");

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    tcg_exec_init(0);
    cpu = cpu_create(X86_CPU_TYPE_NAME("qemu64"));
    if (!cpu)
    {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    tcg_prologue_init(tcg_ctx);

    env->eip = h2g(testcode);

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
