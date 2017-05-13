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

int main(int argc, char **argv, char **envp)
{
    enable_log();
    qemu_log("Hello qemu user\n");

    MessageBoxA(NULL, "Hello qemu user through the Windows API", "Test box!!", MB_OK);
    return 0;
}
