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
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <wine/debug.h>

#include "qemu/osdep.h"
#include "qemu-version.h"

#include "qapi/error.h"
#include "qemu.h"
#include "pe.h"

static HMODULE load_libray(const WCHAR *name);

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
    WCHAR name[MAX_PATH];
    WCHAR fullpath[MAX_PATH];
    unsigned int ref;
};

static struct library_cache_entry *library_cache;
static unsigned int library_cache_size, loaded_libraries;

static inline void *get_rva(HMODULE module, DWORD va)
{
    return (void *)((char *)module + va);
}

HMODULE qemu_GetModuleHandleEx(DWORD flags, const WCHAR *name)
{
    unsigned int i;

    if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
        fprintf(stderr, "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS not implemented\n");
    if (flags & GET_MODULE_HANDLE_EX_FLAG_PIN)
        fprintf(stderr, "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS not implemented\n");

    if (!name)
        return guest_PEB.ImageBaseAddress;

    for (i = 0; i < library_cache_size; ++i)
    {
        if (!library_cache[i].mod)
            continue;
        if (!lstrcmpiW(name, library_cache[i].name))
        {
            qemu_log_mask(LOG_WIN32, "Already loaded library %s\n", wine_dbgstr_w(name));
            if (!(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))
                library_cache[i].ref++;
            return library_cache[i].mod;
        }
    }

    qemu_log_mask(LOG_WIN32, "Module %s not yet loaded\n", wine_dbgstr_w(name));

    return NULL;
}

DWORD qemu_GetModuleFileName(HMODULE module, WCHAR *filename, DWORD size)
{
    unsigned int i;

    if (!module)
        module = qemu_GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, NULL);

    for (i = 0; i < library_cache_size; ++i)
    {
        if (module != library_cache[i].mod)
            continue;

        i = lstrlenW(library_cache[i].fullpath) + 1;
        if (i < size)
        {
            memcpy(filename, library_cache[i].fullpath, i * sizeof(*filename));
            return i;
        }
        else
        {
            memcpy(filename, library_cache[i].fullpath, size * sizeof(*filename));
            filename[size - 1] = 0;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return size;
        }
    }

    return 0;
}

HMODULE qemu_LoadLibrary(const WCHAR *name)
{
    HMODULE ret;

    ret = qemu_GetModuleHandleEx(0, name);
    if (!ret)
        ret = load_libray(name);

    return ret;
}

const void *qemu_GetProcAddress(HMODULE module, const char *name)
{
    ULONG export_size;
    unsigned int i;
    const IMAGE_EXPORT_DIRECTORY *exports = NULL;
    const DWORD *names, *functions;

    exports = RtlImageDirectoryEntryToData(module, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &export_size);
    if (!exports)
    {
        fprintf(stderr, "Module has no exports\n");
        return NULL;
    }

    names = get_rva(module, exports->AddressOfNames);
    functions = get_rva(module, exports->AddressOfFunctions);
    for (i = 0; i < exports->NumberOfFunctions; ++i)
    {
        const char *exportname = get_rva(module, names[i]);
        const void *funcptr = get_rva(module, functions[i]);
        if (!strcmp(exportname, name))
        {
            if ((const char *)funcptr >= (const char *)exports &&
                    (const char *)funcptr < (const char *)exports + export_size)
            {
                static const WCHAR dot_dll[] = {'.', 'd', 'l', 'l', 0};
                char *func, *copy = strdup((const char *)funcptr);
                WCHAR *dll;

                qemu_log_mask(LOG_WIN32, "Export %s is a forward to %s!\n", name, copy);
                func = strrchr(copy, '.');
                *func = 0;
                func++;
                qemu_log_mask(LOG_WIN32, "Dll %s export %s\n", copy, func);

                dll = my_alloc(sizeof(dll) * (strlen(copy) + 4));
                MultiByteToWideChar(CP_ACP, 0, copy, -1, dll, strlen(copy) + 4);
                lstrcatW(dll, dot_dll);
                module = qemu_LoadLibrary(dll);
                my_free(dll);
                if (module)
                {
                    funcptr = qemu_GetProcAddress(module, func);
                    qemu_log_mask(LOG_WIN32, "Found export %s in DLL %s.dll(%p)\n", func, copy, module);
                }
                else
                {
                    fprintf(stderr, "Module %s.dll for forwarded export %s.%s not found.\n", copy,
                            copy, func);
                    funcptr = NULL;
                }

                free(copy);
            }
            return funcptr;
        }
    }
    fprintf(stderr, "Export %s not found.\n", name);
    return NULL;
}

static BOOL fixup_imports(HMODULE module, const IMAGE_IMPORT_DESCRIPTOR *imports)
{
    unsigned int i;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)module;
    const struct nt_header *nt = (const struct nt_header *)((const char *)dos + dos->e_lfanew);

    for (i = 0; imports && imports[i].Name; ++i)
    {
        HMODULE lib;
        const char *lib_name = get_rva(module, imports[i].Name);
        WCHAR *lib_nameW;

        qemu_log_mask(LOG_WIN32, "Module imports library %s\n", lib_name);
        lib_nameW = my_alloc(sizeof(*lib_nameW) * (strlen(lib_name) + 1));
        MultiByteToWideChar(CP_ACP, 0, lib_name, -1, lib_nameW, strlen(lib_name) + 1);
        lib = qemu_LoadLibrary(lib_nameW);
        my_free(lib_nameW);
        if (!lib)
        {
            fprintf(stderr, "Required library %s not found\n", lib_name);
            return FALSE;
        }

        if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            IMAGE_THUNK_DATA64 *thunk;
            thunk = get_rva(module, imports[i].FirstThunk);

            while(thunk->u1.Function)
            {
                IMAGE_IMPORT_BY_NAME *function_name = get_rva(module, thunk->u1.Function);
                const void *impl = qemu_GetProcAddress(lib, (const char *)function_name->Name);
                if (!impl)
                {
                    fprintf(stderr, "Imported symbol %s not found in %s.\n",
                            function_name->Name, lib_name);
                    return FALSE;
                }
                qemu_log_mask(LOG_WIN32, "writing %s to %p\n", function_name->Name, thunk);
                *(const void **)thunk = impl; /* FIXME: Why do I need the offset? */
                thunk++;
            }
        }
        else
        {
            fprintf(stderr, "Implement 32 bit imports\n");
            return FALSE;
        }
    }

    return TRUE;
}

/* Code copied from Wine. This function is exported from ntdll, but the ARM version
 * of ntdll can't deal with IMAGE_REL_BASED_DIR64, so we need our own implementation. */
static IMAGE_BASE_RELOCATION * qemu_LdrProcessRelocationBlock(void *page, UINT count,
        USHORT *relocs, INT_PTR delta)
{
    while (count--)
    {
        USHORT offset = *relocs & 0xfff;
        int type = *relocs >> 12;
        switch(type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(short *)((char *)page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(short *)((char *)page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(int *)((char *)page + offset) += delta;
            break;
        case IMAGE_REL_BASED_DIR64:
            *(INT_PTR *)((char *)page + offset) += delta;
            break;
        default:
            fprintf(stderr, "Unknown/unsupported fixup type %x.\n", type);
            return NULL;
        }
        relocs++;
    }
    return (IMAGE_BASE_RELOCATION *)relocs;  /* return address of next block */
}

/* Code copied from Wine. */
static BOOL relocate_image(HMODULE module, SIZE_T len)
{
    IMAGE_NT_HEADERS *nt;
    char *base;
    IMAGE_BASE_RELOCATION *rel, *end;
    const IMAGE_DATA_DIRECTORY *relocs;
    const IMAGE_SECTION_HEADER *sec;
    INT_PTR delta;
    ULONG protect_old[96], i;
    SYSTEM_INFO sysinfo;

    nt = RtlImageNtHeader(module);
    base = (char *)nt->OptionalHeader.ImageBase;

    GetSystemInfo(&sysinfo);
    /* no relocations are performed on non page-aligned binaries */
    if (nt->OptionalHeader.SectionAlignment < sysinfo.dwPageSize)
        return STATUS_SUCCESS;

    /* Copied from Wine, not sure what this is supposed to do. I guess it triggers in case someone
     * uses LoadLibrary to load a .exe file. */
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL) && guest_PEB.ImageBaseAddress)
    {
        fprintf(stderr, "Not relocating because I am loading a second .exe???\n");
        return STATUS_SUCCESS;
    }

    relocs = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    {
        fprintf(stderr, "Need to relocate module from %p to %p, but there are no relocation records\n",
              base, module);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    if (!relocs->Size)
    {
        qemu_log_mask(LOG_WIN32, "Reloc has zero size\n");
        return STATUS_SUCCESS;
    }
    if (!relocs->VirtualAddress) return STATUS_CONFLICTING_ADDRESSES;

    if (nt->FileHeader.NumberOfSections > sizeof(protect_old)/sizeof(protect_old[0]))
        return STATUS_INVALID_IMAGE_FORMAT;

    sec = (const IMAGE_SECTION_HEADER *)((const char *)&nt->OptionalHeader +
                                         nt->FileHeader.SizeOfOptionalHeader);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = get_rva(module, sec[i].VirtualAddress);
        SIZE_T size = sec[i].SizeOfRawData;
        VirtualProtect(addr, size, PAGE_READWRITE, &protect_old[i]);
    }

    qemu_log_mask(LOG_WIN32, "relocating from %p-%p to %p-%p\n",
           base, base + len, module, (char *)module + len );

    rel = get_rva(module, relocs->VirtualAddress);
    end = get_rva(module, relocs->VirtualAddress + relocs->Size);
    delta = (char *)module - base;

    while (rel < end - 1 && rel->SizeOfBlock)
    {
        if (rel->VirtualAddress >= len)
        {
            qemu_log_mask(LOG_WIN32, "invalid address %p in relocation %p\n",
                    get_rva(module, rel->VirtualAddress), rel);
            return STATUS_ACCESS_VIOLATION;
        }
        rel = qemu_LdrProcessRelocationBlock(get_rva(module, rel->VirtualAddress),
                (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT),
                (USHORT *)(rel + 1), delta);
        if (!rel) return STATUS_INVALID_IMAGE_FORMAT;
    }

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = get_rva(module, sec[i].VirtualAddress);
        SIZE_T size = sec[i].SizeOfRawData;
        VirtualProtect(addr, size, protect_old[i], &protect_old[i]);
    }

    return STATUS_SUCCESS;
}

static HMODULE load_libray(const WCHAR *name)
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
    const IMAGE_IMPORT_DESCRIPTOR *imports = NULL, *imports2;
    WCHAR new_name[MAX_PATH + 10];
    const WCHAR *load_name = name;
    struct library_cache_entry *new_cache;

    if (lstrlenW(name) > (ARRAY_SIZE(library_cache[0].name) - 1))
    {
        fprintf(stderr, "Implement proper library name strings.\n");
        return NULL;
    }

    file = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        static const WCHAR qemu_guest_dll[] = {'q', 'e', 'm', 'u', '_', 'g', 'u', 'e', 's', 't', '_', 'd', 'l', 'l', '\\', 0};

        /* FIXME: Implement a proper search path system. */
        lstrcpyW(new_name, qemu_guest_dll);
        lstrcatW(new_name, name);
        file = CreateFileW(new_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
            qemu_log_mask(LOG_WIN32, "CreateFileW failed.\n");
            goto error;
        }
        load_name = new_name;
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
        base = VirtualAlloc(NULL, image_size, MEM_RESERVE, PAGE_READONLY);
        if (!base)
        {
            fprintf(stderr, "Failed to reserve address space for image!\n");
            goto error;
        }
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
        void *location = get_rva(base, section[i].VirtualAddress);
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

    if (base != image_base && relocate_image(base, image_size) != STATUS_SUCCESS)
    {
        fprintf(stderr, "Relocate failed\n");
        goto error;
    }

    imports2 = RtlImageDirectoryEntryToData(base, TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &read);
    if (imports2)
        imports = imports2;
    else
        fprintf(stderr, "Did not find IMAGE_DIRECTORY_ENTRY_IMPORT, idata at %p.\n", imports);

    if (!fixup_imports(base, imports))
        goto error;

    if (loaded_libraries >= library_cache_size)
    {
        if (!library_cache)
        {
            new_cache = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*new_cache));
            if (!new_cache)
            {
                fprintf(stderr, "Out of memory\n");
                goto error;
            }
            library_cache_size = 1;
        }
        else
        {
            new_cache = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                    library_cache, sizeof(*new_cache) * library_cache_size * 2);
            if (!new_cache)
            {
                fprintf(stderr, "Out of memory\n");
                goto error;
            }
            library_cache_size *= 2;
        }
        library_cache = new_cache;
    }

    for (i = 0; i < library_cache_size; ++i)
    {
        if (!library_cache[i].mod)
        {
            library_cache[i].mod = base;
            library_cache[i].ref = 1;
            lstrcpyW(library_cache[i].name, name);
            GetFullPathNameW(load_name, ARRAY_SIZE(library_cache[i].fullpath), library_cache[i].fullpath, NULL);
            loaded_libraries++;
            return base;
        }
    }
    fprintf(stderr, "Library cache error.\n");

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

BOOL qemu_FreeLibrary(HMODULE module)
{
    fprintf(stderr, "FreeLibrary unimplemented\n");
    return TRUE;
}
