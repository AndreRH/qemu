/*
 *  Windows syscall handler
 *
 *  Copyright (c) 2017 Stefan Dösinger
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
#include "win_syscall.h"

static const syscall_handler **dlls;
static unsigned int dll_count;

static const struct qemu_ops ops =
{
    12345
};

BOOL load_host_dlls(void)
{
    const syscall_handler *handlers;
    uint32_t dll_num;
    
    dlls = my_alloc(sizeof(*dlls) * 2);
    if (!dlls)
        return FALSE;
    
    do
    {
        syscall_lib_register fn;

        HANDLE h = LoadLibraryA("qemu_host_dll\\qemu_kernel32.dll.so");
        if (!h)
        {
            fprintf(stderr, "Unable to load library\n");
            return FALSE;
        }
        
        fn = (syscall_lib_register)GetProcAddress(h, "qemu_dll_register");
        if (!fn)
        {
            fprintf(stderr, "No register export\n");
            return FALSE;
        }
        
         handlers = fn(&ops, &dll_num);
         dlls[dll_num] = handlers;
    } while(0);
    dll_count = 1;
    
    return TRUE;
}

void do_syscall(struct qemu_syscall *call)
{
    uint32_t dll = call->id >> 32;
    uint32_t func = call->id & 0xffffffff;
    
    qemu_log_mask(LOG_WIN32, "Handling syscall %16lx\n", call->id);
    
    dlls[dll][func](call);
}
