/*
 *  qemu PE executable and library loader
 *
 *  Copyright (C) 1999 Alexandre Julliard
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

#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#include "qemu/osdep.h"
#include "qemu-version.h"

#include "qapi/error.h"
#include "qemu.h"
#include "pe.h"

static HMODULE load_libray(const char *name);

struct nt_header
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    union
    {
        IMAGE_OPTIONAL_HEADER32 hdr32;
        IMAGE_OPTIONAL_HEADER64 hdr64;
    } opt;
};

struct library_cache_entry
{
    HMODULE mod;
    char name[MAX_PATH];
    unsigned int ref;
};

static struct library_cache_entry library_cache[128];

static HMODULE qemu_GetModuleHandle(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(library_cache); ++i)
    {
        if (!library_cache[i].mod)
            continue;
        if (!strcmp(name, library_cache[i].name))
        {
            qemu_log_mask(LOG_WIN32, "Already loaded library %s\n", name);
            library_cache[i].ref++;
            return library_cache[i].mod;
        }
    }

    qemu_log_mask(LOG_WIN32, "Module %s not yet loaded\n", name);

    return NULL;
}

HMODULE qemu_LoadLibraryA(const char *name)
{
    HMODULE ret;

    ret = qemu_GetModuleHandle(name);
    if (!ret)
        ret = load_libray(name);

    return ret;
}

static const void *qemu_GetProcAddress(HMODULE module, const char *name)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)module;
    const struct nt_header *nt = (const struct nt_header *)((const char *)dos + dos->e_lfanew);
    SIZE_T fixed_header_size = 0;
    unsigned int i;
    const IMAGE_EXPORT_DIRECTORY *exports = NULL;
    const IMAGE_SECTION_HEADER *section;
    const DWORD *names, *functions;

    fixed_header_size = dos->e_lfanew + sizeof(nt->Signature) + sizeof(nt->FileHeader);
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        fixed_header_size += sizeof(nt->opt.hdr64);
    }
    else
    {
        fixed_header_size += sizeof(nt->opt.hdr32);
    }

    section = (const IMAGE_SECTION_HEADER *)((char *)module + fixed_header_size);

    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (!memcmp(section[i].Name, ".edata", strlen(".edata")))
        {
            exports = (const IMAGE_EXPORT_DIRECTORY *)((char *)module + section[i].VirtualAddress);
            break;
        }
    }

    if (!exports)
    {
        fprintf(stderr, "Module has no exports\n");
        return NULL;
    }

    names = (DWORD *)((char *)module + exports->AddressOfNames);
    functions = (DWORD *)((char *)module + exports->AddressOfFunctions);
    for (i = 0; i < exports->NumberOfFunctions; ++i)
    {
        const char *exportname = (const char *)module + names[i];
        const void *funcptr = (const char *)module + functions[i];
        if (!strcmp(exportname, name))
            return funcptr;
    }
    fprintf(stderr, "Export %s not found.\n", name);
    return NULL;
}

static HMODULE load_libray(const char *name)
{
    HANDLE file;
    IMAGE_DOS_HEADER dos;
    struct nt_header nt;
    BOOL ret;
    DWORD read;
    SIZE_T image_size, header_size;
    void *image_base;
    SIZE_T fixed_header_size;
    unsigned int i;
    void *base = NULL, *alloc;
    const IMAGE_SECTION_HEADER *section;
    const IMAGE_IMPORT_DESCRIPTOR *imports = NULL;

    if (strlen(name) > (ARRAY_SIZE(library_cache[0].name) - 1))
    {
        fprintf(stderr, "Implement proper library name strings.\n");
        return NULL;
    }

    file = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        char new_name[MAX_PATH + 10];

        /* FIXME: Implement a proper search path system. */
        sprintf(new_name, "qemu_guest_dll\\%s", name);
        file = CreateFileA(new_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
            qemu_log_mask(LOG_WIN32, "CreateFileA failed.\n");
            goto error;
        }
    }

    ret = ReadFile(file, &dos, sizeof(dos), &read, NULL);
    if (!ret || read != sizeof(dos))
    {
        fprintf(stderr, "Failed to read DOS header.\n");
        goto error;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(stderr, "Invalid DOS signature.\n");
        goto error;
    }

    SetFilePointer(file, dos.e_lfanew, NULL, FILE_BEGIN);
    ret = ReadFile(file, &nt, sizeof(nt), &read, NULL);
    if (!ret || read != sizeof(nt))
    {
        fprintf(stderr, "Failed to read PE header.\n");
        goto error;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "Invalid NT signature.\n");
        goto error;
    }

    fixed_header_size = dos.e_lfanew + sizeof(nt.Signature) + sizeof(nt.FileHeader);

    switch (nt.FileHeader.Machine)
    {
        case IMAGE_FILE_MACHINE_I386:
            if (nt.opt.hdr64.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                fprintf(stderr, "Wrong optional header magic.\n");
                goto error;
            }
            image_base = (void *)(DWORD_PTR)nt.opt.hdr32.ImageBase;
            image_size = nt.opt.hdr32.SizeOfImage;
            header_size = nt.opt.hdr32.SizeOfHeaders;
            fixed_header_size += sizeof(nt.opt.hdr32);
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            if (nt.opt.hdr64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                fprintf(stderr, "Wrong optional header magic.\n");
                goto error;
            }
            image_base = (void *)nt.opt.hdr64.ImageBase;
            image_size = nt.opt.hdr64.SizeOfImage;
            header_size = nt.opt.hdr64.SizeOfHeaders;
            fixed_header_size += sizeof(nt.opt.hdr64);
            break;
        default:
            fprintf(stderr, "Unsupported machine %d.\n", nt.FileHeader.Machine);
            goto error;
    }

    /* Why not use CreateFileMapping(SEC_IMAGE) and remove most of the code in this
     * function you ask? Because SEC_IMAGE only works with files that have a matching
     * target CPU, at least in Wine. This is also a large part why we need the custom
     * loader and can't just do LoadLibraryEx(DON'T_RESOLVE_DLL_REFERENCES).
     * GetModuleHandle is the other big problem we're facing with mixing libs of two
     * architectures in the same process.
     *
     * Unfortunately Windows has no way to reserve an area of address space and then
     * map file(s) into it later. The other problem is that MapViewOfFile needs 64k
     * aligned offsets, but PE section alignment is 4k. So alloc anonymous memory and
     * read the file contents into it.
     *
     * A future optimization could try to map as much read-only data as possible from
     * the file and alloc+read the rest. We'd probably manage headers + .text, which
     * I expect to be the majority of the file. */

    qemu_log_mask(LOG_WIN32, "Trying to map file size %lu at %p.\n", (unsigned long)image_size, image_base);
    base = VirtualAlloc(image_base, image_size, MEM_RESERVE, PAGE_READONLY);
    qemu_log_mask(LOG_WIN32, "Got %p\n", base);
    if (!base)
    {
        fprintf(stderr, "FIXME: Implement relocations!\n");
        goto error;
    }

    alloc = VirtualAlloc(base, header_size, MEM_COMMIT, PAGE_READWRITE);
    if (!alloc)
    {
        fprintf(stderr, "Failed to commit memory for image headers.\n");
        goto error;
    }
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    ret = ReadFile(file, base, header_size, &read, NULL);
    if (!ret || read != header_size)
    {
        fprintf(stderr, "Failed to read image headers.\n");
        goto error;
    }
    /* TODO: Write-protect the headers. */

    section = (const IMAGE_SECTION_HEADER *)((char *)base + fixed_header_size);
    qemu_log_mask(LOG_WIN32, "Got %u sections at %p\n", nt.FileHeader.NumberOfSections, section);

    for (i = 0; i < nt.FileHeader.NumberOfSections; i++)
    {
        void *location = ((char *)base + section[i].VirtualAddress);
        SIZE_T map_size = section[i].Misc.VirtualSize;
        qemu_log_mask(LOG_WIN32, "Mapping section %8s at %p.\n", section[i].Name, location);
        DWORD protect, old_protect;

        alloc = VirtualAlloc(location, map_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!alloc)
        {
            fprintf(stderr, "Failed to commit memory for section %8s.\n", section[i].Name);
            goto error;
        }

        if (section[i].SizeOfRawData)
        {
            qemu_log_mask(LOG_WIN32, "Reading %8s from 0x%x to %p.\n",
                    section[i].Name, section[i].PointerToRawData, location);

            SetFilePointer(file, section[i].PointerToRawData, NULL, FILE_BEGIN);
            ret = ReadFile(file, alloc, section[i].SizeOfRawData, &read, NULL);
            if (!ret || read != section[i].SizeOfRawData)
            {
                fprintf(stderr, "Failed to read section %8s.\n", section[i].Name);
                goto error;
            }
        }

        /* Everything that has write but not read probably doesn't make sense. There is
         * no PAGE_WRITEONLY or PAGE_WRITEEXECUTE flag. And writing at a poor alignment
         * probably requires a read anyway. */
        switch (section[i].Characteristics
                & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
        {
            case IMAGE_SCN_MEM_READ:
                qemu_log_mask(LOG_WIN32, "Section %s is read-only.\n", section[i].Name);
                protect = PAGE_READONLY;
                break;
            case IMAGE_SCN_MEM_WRITE:
                qemu_log_mask(LOG_WIN32, "Section %s is write-only.\n", section[i].Name);
                protect = PAGE_READWRITE;
                break;
            case IMAGE_SCN_MEM_EXECUTE:
                qemu_log_mask(LOG_WIN32, "Section %s is execute-only.\n", section[i].Name);
                protect = PAGE_EXECUTE;
                break;

            case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
                qemu_log_mask(LOG_WIN32, "Section %s is read-write.\n", section[i].Name);
                protect = PAGE_READWRITE;
                break;
            case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE:
                qemu_log_mask(LOG_WIN32, "Section %s is read-execute.\n", section[i].Name);
                protect = PAGE_EXECUTE_READ;
                break;
            case IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE:
                qemu_log_mask(LOG_WIN32, "Section %s is write-execute.\n", section[i].Name);
                protect = PAGE_EXECUTE_READWRITE;
                break;

            case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE:
                qemu_log_mask(LOG_WIN32, "Section %s is read-write-execute.\n", section[i].Name);
                protect = PAGE_EXECUTE_READWRITE;
                break;

            default:
                fprintf(stderr, "Forgot to handle %x.\n", section[i].Characteristics);
                protect = PAGE_EXECUTE_READWRITE;
        }
        if (protect != PAGE_EXECUTE_READWRITE && !VirtualProtect(alloc, map_size, protect, &old_protect))
            fprintf(stderr, "VirtualProtect failed.\n");

        if (!memcmp(section[i].Name, ".idata", 6))
            imports = alloc;
    }

    for (i = 0; imports && imports[i].Name; ++i)
    {
        HMODULE lib;
        const char *lib_name = (char *)base + imports[i].Name;
        qemu_log_mask(LOG_WIN32, "File %s imports library %s\n", name, lib_name);
        lib = qemu_LoadLibraryA(lib_name);
        if (!lib)
        {
            fprintf(stderr, "Required library %s not found\n", lib_name);
            goto error;
        }

        if (nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            IMAGE_THUNK_DATA64 *thunk;
            thunk = (IMAGE_THUNK_DATA64 *)((char *)base + imports[i].FirstThunk);

            while(thunk->u1.Function)
            {
                IMAGE_IMPORT_BY_NAME *function_name =
                        (IMAGE_IMPORT_BY_NAME *)((char *)base + thunk->u1.Function);
                const void *impl = qemu_GetProcAddress(lib, (const char *)function_name->Name);
                if (!impl)
                {
                    fprintf(stderr, "Imported symbol %s not found in %s.\n",
                            function_name->Name, lib_name);
                    goto error;
                }
                qemu_log_mask(LOG_WIN32, "writing to %p\n", thunk);
                *(const void **)thunk = impl; /* FIXME: Why do I need the offset? */
                thunk++;
            }
        }
        else
        {
            fprintf(stderr, "Implement 32 bit imports\n");
            goto error;
        }
    }

    for (i = 0; i < ARRAY_SIZE(library_cache); ++i)
    {
        if (!library_cache[i].mod)
        {
            library_cache[i].mod = (HMODULE)base;
            library_cache[i].ref = 1;
            strcpy(library_cache[i].name, name);
            break;
        }
    }

    if (i == ARRAY_SIZE(library_cache))
        fprintf(stderr, "Lib cache too small\n");

    return (HMODULE)base;

error:
    if (base)
        VirtualFree(base, 0, MEM_RELEASE);
    if (file)
        CloseHandle(file);

    return NULL;
}

void qemu_get_image_info(const HMODULE module, struct qemu_pe_image *info)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)module;
    const struct nt_header *nt = (const struct nt_header *)((const char *)dos + dos->e_lfanew);
    
    info->entrypoint = (void *)((char *)module) + nt->opt.hdr64.AddressOfEntryPoint;
    info->stack_reserve = nt->opt.hdr64.SizeOfStackReserve;
    info->stack_commit = nt->opt.hdr64.SizeOfStackCommit;
}
