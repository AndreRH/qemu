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

struct load_host_dlls
{
    const syscall_handler *handlers;
    HANDLE module;
};

static struct load_host_dlls *dlls;
static unsigned int dll_count;

static const struct qemu_ops ops =
{
    12345
};

BOOL load_host_dlls(void)
{
    const syscall_handler *handlers;
    uint32_t dll_num;
    unsigned int loaded_dlls = 0;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    const syscall_handler **new_ptr;
    char path[MAX_PATH];
    
    dll_count = 2;
    dlls = my_alloc(sizeof(*dlls) * dll_count);
    if (!dlls)
        return FALSE;
    memset(dlls, 0, sizeof(*dlls) * dll_count);

    find_handle = FindFirstFileA("qemu_host_dll\\*", &find_data);
    if (find_handle == INVALID_HANDLE_VALUE)
    {
        goto error;
    }

    do
    {
        syscall_lib_register fn;

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        sprintf(path, "qemu_host_dll\\%s", find_data.cFileName);
        HANDLE h = LoadLibraryA(path);
        if (!h)
        {
            fprintf(stderr, "Unable to load library %s.\n", path);
            continue;
        }
        
        fn = (syscall_lib_register)GetProcAddress(h, "qemu_dll_register");
        if (!fn)
        {
            fprintf(stderr, "No register export\n");
            FreeLibrary(h);
            continue;
        }
        
        handlers = fn(&ops, &dll_num);

        if (dll_count <= dll_num)
        {
            new_ptr = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dlls, sizeof(*dlls) * (dll_num + 1));
            if (!new_ptr)
            {
                fprintf(stderr, "Out of memory.\n");
                FreeLibrary(h);
                FindClose(find_handle);
                goto error;
            }
            dll_count = dll_num + 1;
        }

        dlls[dll_num].handlers = handlers;
        dlls[dll_num].module = h;
        loaded_dlls++;
    }
    while(FindNextFile(find_handle, &find_data));

    FindClose(find_handle);

    if (loaded_dlls)
        return TRUE;

    fprintf(stderr, "Did not manage to load any host DLLs.\n");

error:
    for (loaded_dlls = 0; loaded_dlls < dll_count; ++loaded_dlls)
    {
        if (dlls[loaded_dlls].module)
            FreeLibrary(dlls[loaded_dlls].module);
    }

    if (dlls)
        my_free(dlls);
    return FALSE;
}

void do_syscall(struct qemu_syscall *call)
{
    uint32_t dll = call->id >> 32;
    uint32_t func = call->id & 0xffffffff;
    
    qemu_log_mask(LOG_WIN32, "Handling syscall %16lx\n", call->id);
    
    dlls[dll].handlers[func](call);
}
