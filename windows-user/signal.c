/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *  Copyright (c) 2017 André Hentschel
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
    siginfo_t info;
    ucontext_t uc;

    if (!cpu || !cpu->running)
    {
        /* FIXME: Unsure about +env->segs[R_CS].base */
        fprintf(stderr, "Exception triggered in host code at %p, guest PC %lx\n",
                exception->ExceptionRecord->ExceptionAddress, env->eip + env->segs[R_CS].base);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    memset(&info, 0, sizeof(info));
    info.si_addr = exception->ExceptionRecord->ExceptionAddress;

    memset(&uc, 0, sizeof(uc));
    // uc.uc_mcontext.pc = (unsigned long)exception->ExceptionRecord->ExceptionAddress;
    /* uc.uc_sigmask = FIXME */

    switch (exception->ExceptionRecord->ExceptionCode)
    {
        case EXCEPTION_ACCESS_VIOLATION:
            cpu_signal_handler(SIGSEGV, &info, &uc);
            fprintf(stderr, "Did not expect cpu_signal_handler to return.\n");

        default:
            fprintf(stderr, "Handle exception code %x\n", exception->ExceptionRecord->ExceptionCode);
            cpu_restore_state(cpu, (uintptr_t)exception->ExceptionRecord->ExceptionAddress + GETPC_ADJ, true);
            cpu_dump_state(cpu, stderr, fprintf, 0);
            ExitProcess(EXIT_FAILURE);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


void signal_init(void)
{
    SetUnhandledExceptionFilter(exception_handler);
}
