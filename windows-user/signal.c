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

#include "qemu.h"

static LONG WINAPI exception_handler(EXCEPTION_POINTERS *exception)
{
    CPUX86State *env = thread_cpu->env_ptr;
    CPUState *cpu = ENV_GET_CPU(env);

    /* FIXME: Check for host exception */
    /* FIXME: Unsure about cpu_exit and +env->segs[R_CS].base */
    cpu_exit(thread_cpu);
    fprintf(stderr, "Unhandled exception triggered at %lx\n", env->eip + env->segs[R_CS].base);
    cpu_dump_state(cpu, stderr, fprintf, 0);
    ExitProcess(EXIT_FAILURE);
    return EXCEPTION_CONTINUE_SEARCH;
}


void signal_init(void)
{
    SetUnhandledExceptionFilter(exception_handler);
}
