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
#include "config.h"

#include <wine/port.h>
#include <wine/library.h>
#include <wine/debug.h>

#include "qemu/osdep.h"
#include "qemu-version.h"

#include "qapi/error.h"
#include "qemu.h"
#include "win_syscall.h"
#include "delayloadhandler.h"
#include "pe.h"

WINE_DECLARE_DEBUG_CHANNEL(heap);

struct load_host_dlls
{
    const syscall_handler *handlers;
    HMODULE module;
};

static struct load_host_dlls *dlls;
static unsigned int dll_count;

static void qemu_set_except_handler(uint64_t handler)
{
    guest_exception_handler = handler;
}

static void qemu_set_call_entry(uint64_t call_entry)
{
    guest_call_entry = call_entry;
}

static const struct qemu_ops ops =
{
    qemu_execute,
    qemu_FreeLibrary,
    qemu_GetModuleFileName,
    qemu_GetModuleHandleEx,
    qemu_GetProcAddress,
    (void *)qemu_getTEB, /* Cast for (TEB *) -> (void *) */
    qemu_getTEB32, /* Cast for (TEB32 *) -> (void *) */
    qemu_LoadLibrary,
    qemu_set_except_handler,
    qemu_set_call_entry,
    qemu_FindEntryForAddress,
    qemu_DisableThreadLibraryCalls,
    qemu_get_ldr_module,
    qemu_RtlPcToFileHeader,
    qemu_DllMain,
    qemu_set_context,
};

BOOL load_host_dlls(BOOL load_msvcrt)
{
    const syscall_handler *handlers;
    uint32_t dll_num;
    unsigned int loaded_dlls = 0;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    struct load_host_dlls *new_ptr;
    char path[MAX_PATH + 30];

    if (!dlls)
    {
        dll_count = 2;
        dlls = my_alloc(sizeof(*dlls) * dll_count);
        if (!dlls)
            return FALSE;
        memset(dlls, 0, sizeof(*dlls) * dll_count);
    }

    GetModuleFileNameA(NULL, path, MAX_PATH);
    pPathRemoveFileSpecA(path);
    if (is_32_bit)
        strcat(path, "\\qemu_host_dll32\\*");
    else
        strcat(path, "\\qemu_host_dll64\\*");
    find_handle = FindFirstFileA(path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE)
    {
        goto error;
    }

    do
    {
        syscall_lib_register fn;

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        /* We load the msvcrt libs after the 32 bit VM setup to make sure its
         * gigantic amount of data pointers is accessible. */
        if (!strstr(find_data.cFileName, "qemu_msvcr") == !!load_msvcrt)
            continue;

        if (is_32_bit)
            sprintf(path, "qemu_host_dll32\\%s.", find_data.cFileName);
        else
            sprintf(path, "qemu_host_dll64\\%s.", find_data.cFileName);
        qemu_log_mask(LOG_WIN32, "trying to load %s\n", path);
        HMODULE mod = LoadLibraryA(path);
        if (!mod)
        {
            fprintf(stderr, "Unable to load library %s.\n", path);
            continue;
        }

        fn = (syscall_lib_register)GetProcAddress(mod, "qemu_dll_register");
        if (!fn)
        {
            fprintf(stderr, "No register export\n");
            FreeLibrary(mod);
            continue;
        }

        handlers = fn(&ops, &dll_num);

        if (dll_count <= dll_num)
        {
            new_ptr = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dlls, sizeof(*dlls) * (dll_num + 1));
            if (!new_ptr)
            {
                fprintf(stderr, "Out of memory.\n");
                FreeLibrary(mod);
                FindClose(find_handle);
                goto error;
            }
            dlls = new_ptr;
            dll_count = dll_num + 1;
        }

        qemu_log_mask(LOG_WIN32, "Registered DLL %s with number %u.\n", path, dll_num);
        dlls[dll_num].handlers = handlers;
        dlls[dll_num].module = mod;
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

    qemu_log_mask(LOG_WIN32, "Handling syscall %16lx.\n", call->id);

    if (WINE_WARN_ON(heap) && !HeapValidate(GetProcessHeap(), 0, NULL))
    {
        fprintf(stderr, "Heap is broken before syscall %lx\n", call->id);
        ExitProcess(1);
    }

    dlls[dll].handlers[func](call);

    if (WINE_WARN_ON(heap) && !HeapValidate(GetProcessHeap(), 0, NULL))
    {
        fprintf(stderr, "Heap is broken after syscall %lx\n", call->id);
        ExitProcess(1);
    }
}
