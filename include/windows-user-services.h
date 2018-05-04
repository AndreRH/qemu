#ifndef QEMU_WINDOWS_USER_SERVICES_H
#define QEMU_WINDOWS_USER_SERVICES_H

#include <stdint.h>

struct qemu_syscall
{
    uint64_t id;
    union
    {
        uint64_t iret;
        float fret;
        double dret;
    };
};

static inline void qemu_syscall(struct qemu_syscall *call)
{
    /* TODO: 32 bit version. */
    asm volatile( "syscall\n"
            : /* no output */
            : "c"(call)
            : "memory");
}

#define QEMU_SYSCALL_ID(a) ((QEMU_CURRENT_DLL << 32ULL) | (a))

static inline uint64_t guest_HANDLE_g2h(HANDLE h)
{
    /* ~0 == Invalid handle == current process, ~1 == current thread, ~3 == current process token,
     * ~4 == GetCurrentThreadToken(), ~5 == GetCurrentThreadEffectiveToken() */
    if (h == INVALID_HANDLE_VALUE || h == (HANDLE)~(ULONG_PTR)1 || h == (HANDLE)~(ULONG_PTR)3
            || h == (HANDLE)~(ULONG_PTR)4 || h == (HANDLE)~(ULONG_PTR)5)
        return (LONG_PTR)h;
    else
        return (ULONG_PTR)h;
}

#ifndef QEMU_DLL_GUEST

#include <winternl.h>

typedef DWORD qemu_ptr, qemu_handle;

typedef struct _NT_TIB32
{
	qemu_ptr ExceptionList;
	qemu_ptr StackBase;
	qemu_ptr StackLimit;
	qemu_ptr SubSystemTib;
	union {
          qemu_ptr FiberData;
          DWORD Version;
	} DUMMYUNIONNAME;
	qemu_ptr ArbitraryUserPointer;
	qemu_ptr Self;
} NT_TIB32, *PNT_TIB32;

typedef struct _UNICODE_STRING32 {
  USHORT Length;        /* bytes */
  USHORT MaximumLength; /* bytes */
  qemu_ptr Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _CLIENT_ID32
{
   qemu_handle UniqueProcess;
   qemu_handle UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _LIST_ENTRY32 {
  qemu_ptr Flink;
  qemu_ptr Blink;
} LIST_ENTRY32, *PLIST_ENTRY32, * RESTRICTED_POINTER PRLIST_ENTRY32;

typedef struct _ACTIVATION_CONTEXT_STACK32
{
    ULONG                               Flags;
    ULONG                               NextCookieSequenceNumber;
    qemu_ptr ActiveFrame;
    LIST_ENTRY32                          FrameListCache;
} ACTIVATION_CONTEXT_STACK32, *PACTIVATION_CONTEXT_STACK32;

typedef struct _GDI_TEB_BATCH32
{
    ULONG  Offset;
    qemu_handle HDC;
    ULONG  Buffer[0x136];
} GDI_TEB_BATCH32;

/***********************************************************************
 * TEB data structure
 */
typedef struct _TEB32
{                                                                 /* win32/win64 */
    NT_TIB32                     Tib;                               /* 000/0000 */
    qemu_ptr                     EnvironmentPointer;                /* 01c/0038 */
    CLIENT_ID32                  ClientId;                          /* 020/0040 */
    qemu_ptr                     ActiveRpcHandle;                   /* 028/0050 */
    qemu_ptr                     ThreadLocalStoragePointer;         /* 02c/0058 */
    qemu_ptr                     Peb;                               /* 030/0060 */
    ULONG                        LastErrorValue;                    /* 034/0068 */
    ULONG                        CountOfOwnedCriticalSections;      /* 038/006c */
    qemu_ptr                     CsrClientThread;                   /* 03c/0070 */
    qemu_ptr                     Win32ThreadInfo;                   /* 040/0078 */
    ULONG                        Win32ClientInfo[31];               /* 044/0080 used for user32 private data in Wine */
    qemu_ptr                        WOW32Reserved;                     /* 0c0/0100 */
    ULONG                        CurrentLocale;                     /* 0c4/0108 */
    ULONG                        FpSoftwareStatusRegister;          /* 0c8/010c */
    qemu_ptr                        SystemReserved1[54];               /* 0cc/0110 used for kernel32 private data in Wine */
    LONG                         ExceptionCode;                     /* 1a4/02c0 */
    ACTIVATION_CONTEXT_STACK32     ActivationContextStack;            /* 1a8/02c8 */
    BYTE                         SpareBytes1[24];                   /* 1bc/02e8 */
    qemu_ptr                        SystemReserved2[10];               /* 1d4/0300 used for ntdll platform-specific private data in Wine */
    GDI_TEB_BATCH32                GdiTebBatch;                       /* 1fc/0350 used for ntdll private data in Wine */
    qemu_handle                       gdiRgn;                            /* 6dc/0838 */
    qemu_handle                       gdiPen;                            /* 6e0/0840 */
    qemu_handle                       gdiBrush;                          /* 6e4/0848 */
    CLIENT_ID32                    RealClientId;                      /* 6e8/0850 */
    qemu_handle                       GdiCachedProcessHandle;            /* 6f0/0860 */
    ULONG                        GdiClientPID;                      /* 6f4/0868 */
    ULONG                        GdiClientTID;                      /* 6f8/086c */
    qemu_ptr                        GdiThreadLocaleInfo;               /* 6fc/0870 */
    ULONG                        UserReserved[5];                   /* 700/0878 */
    qemu_ptr                        glDispatchTable[280];              /* 714/0890 */
    qemu_ptr                        glReserved1[26];                   /* b74/1150 */
    qemu_ptr                        glReserved2;                       /* bdc/1220 */
    qemu_ptr                        glSectionInfo;                     /* be0/1228 */
    qemu_ptr                        glSection;                         /* be4/1230 */
    qemu_ptr                        glTable;                           /* be8/1238 */
    qemu_ptr                        glCurrentRC;                       /* bec/1240 */
    qemu_ptr                        glContext;                         /* bf0/1248 */
    ULONG                        LastStatusValue;                   /* bf4/1250 */
    UNICODE_STRING32             StaticUnicodeString;               /* bf8/1258 used by advapi32 */
    WCHAR                        StaticUnicodeBuffer[261];          /* c00/1268 used by advapi32 */
    qemu_ptr                        DeallocationStack;                 /* e0c/1478 */
    qemu_ptr                        TlsSlots[64];                      /* e10/1480 */
    LIST_ENTRY32                   TlsLinks;                          /* f10/1680 */
    qemu_ptr                        Vdm;                               /* f18/1690 */
    qemu_ptr                        ReservedForNtRpc;                  /* f1c/1698 */
    qemu_ptr                        DbgSsReserved[2];                  /* f20/16a0 */
    ULONG                        HardErrorDisabled;                 /* f28/16b0 */
    qemu_ptr                        Instrumentation[16];               /* f2c/16b8 */
    qemu_ptr                        WinSockData;                       /* f6c/1738 */
    ULONG                        GdiBatchCount;                     /* f70/1740 */
    ULONG                        Spare2;                            /* f74/1744 */
    qemu_ptr                        Spare3;                            /* f78/1748 */
    qemu_ptr                        Spare4;                            /* f7c/1750 */
    qemu_ptr                        ReservedForOle;                    /* f80/1758 */
    ULONG                        WaitingOnLoaderLock;               /* f84/1760 */
    qemu_ptr                        Reserved5[3];                      /* f88/1768 */
    qemu_ptr                       TlsExpansionSlots;                 /* f94/1780 */
    ULONG                        ImpersonationLocale;               /* f98/1788 */
    ULONG                        IsImpersonating;                   /* f9c/178c */
    qemu_ptr                        NlsCache;                          /* fa0/1790 */
    qemu_ptr                        ShimData;                          /* fa4/1798 */
    ULONG                        HeapVirtualAffinity;               /* fa8/17a0 */
    qemu_ptr                        CurrentTransactionHandle;          /* fac/17a8 */
    qemu_ptr                        ActiveFrame;                       /* fb0/17b0 */
    qemu_ptr                       FlsSlots;                          /* fb4/17c8 */
} TEB32, *PTEB32;

typedef struct _CURDIR32
{
    UNICODE_STRING32 DosPath;
    qemu_ptr Handle;
} CURDIR32, *PCURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    ULONG               AllocationSize;
    ULONG               Size;
    ULONG               Flags;
    ULONG               DebugFlags;
    qemu_handle         ConsoleHandle;
    ULONG               ConsoleFlags;
    qemu_handle         hStdInput;
    qemu_handle         hStdOutput;
    qemu_handle         hStdError;
    CURDIR32            CurrentDirectory;
    UNICODE_STRING32    DllPath;
    UNICODE_STRING32    ImagePathName;
    UNICODE_STRING32    CommandLine;
    qemu_ptr            Environment;
    ULONG               dwX;
    ULONG               dwY;
    ULONG               dwXSize;
    ULONG               dwYSize;
    ULONG               dwXCountChars;
    ULONG               dwYCountChars;
    ULONG               dwFillAttribute;
    ULONG               dwFlags;
    ULONG               wShowWindow;
    UNICODE_STRING32    WindowTitle;
    UNICODE_STRING32    Desktop;
    UNICODE_STRING32    ShellInfo;
    UNICODE_STRING32    RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32
{                                                                 /* win32/win64 */
    BOOLEAN                      InheritedAddressSpace;             /* 000/000 */
    BOOLEAN                      ReadImageFileExecOptions;          /* 001/001 */
    BOOLEAN                      BeingDebugged;                     /* 002/002 */
    BOOLEAN                      SpareBool;                         /* 003/003 */
    qemu_handle                  Mutant;                            /* 004/008 */
    qemu_handle                  ImageBaseAddress;                  /* 008/010 */
    qemu_ptr                     LdrData;                           /* 00c/018 */
    qemu_ptr                     ProcessParameters;                 /* 010/020 */
    qemu_ptr                     SubSystemData;                     /* 014/028 */
    qemu_handle                  ProcessHeap;                       /* 018/030 */
    qemu_ptr                     FastPebLock;                       /* 01c/038 */
    qemu_ptr                     FastPebLockRoutine;                /* 020/040 */
    qemu_ptr                     FastPebUnlockRoutine;              /* 024/048 */
    ULONG                        EnvironmentUpdateCount;            /* 028/050 */
    qemu_ptr                     KernelCallbackTable;               /* 02c/058 */
    ULONG                        Reserved[2];                       /* 030/060 */
    qemu_ptr                     FreeList;                          /* 038/068 */
    ULONG                        TlsExpansionCounter;               /* 03c/070 */
    qemu_ptr                     TlsBitmap;                         /* 040/078 */
    ULONG                        TlsBitmapBits[2];                  /* 044/080 */
    qemu_ptr                     ReadOnlySharedMemoryBase;          /* 04c/088 */
    qemu_ptr                     ReadOnlySharedMemoryHeap;          /* 050/090 */
    qemu_ptr                     ReadOnlyStaticServerData;          /* 054/098 */
    qemu_ptr                     AnsiCodePageData;                  /* 058/0a0 */
    qemu_ptr                     OemCodePageData;                   /* 05c/0a8 */
    qemu_ptr                     UnicodeCaseTableData;              /* 060/0b0 */
    ULONG                        NumberOfProcessors;                /* 064/0b8 */
    ULONG                        NtGlobalFlag;                      /* 068/0bc */
    LARGE_INTEGER                CriticalSectionTimeout;            /* 070/0c0 */
    qemu_handle                  HeapSegmentReserve;                /* 078/0c8 */
    qemu_handle                  HeapSegmentCommit;                 /* 07c/0d0 */
    qemu_handle                  HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
    qemu_handle                  HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
    ULONG                        NumberOfHeaps;                     /* 088/0e8 */
    ULONG                        MaximumNumberOfHeaps;              /* 08c/0ec */
    qemu_ptr                     ProcessHeaps;                      /* 090/0f0 */
    qemu_ptr                     GdiSharedHandleTable;              /* 094/0f8 */
    qemu_ptr                     ProcessStarterHelper;              /* 098/100 */
    qemu_ptr                     GdiDCAttributeList;                /* 09c/108 */
    qemu_ptr                     LoaderLock;                        /* 0a0/110 */
    ULONG                        OSMajorVersion;                    /* 0a4/118 */
    ULONG                        OSMinorVersion;                    /* 0a8/11c */
    ULONG                        OSBuildNumber;                     /* 0ac/120 */
    ULONG                        OSPlatformId;                      /* 0b0/124 */
    ULONG                        ImageSubSystem;                    /* 0b4/128 */
    ULONG                        ImageSubSystemMajorVersion;        /* 0b8/12c */
    ULONG                        ImageSubSystemMinorVersion;        /* 0bc/130 */
    ULONG                        ImageProcessAffinityMask;          /* 0c0/134 */
    qemu_handle                  GdiHandleBuffer[28];               /* 0c4/138 */
    ULONG                        unknown[6];                        /* 134/218 */
    qemu_ptr                     PostProcessInitRoutine;            /* 14c/230 */
    qemu_ptr                     TlsExpansionBitmap;                /* 150/238 */
    ULONG                        TlsExpansionBitmapBits[32];        /* 154/240 */
    ULONG                        SessionId;                         /* 1d4/2c0 */
    ULARGE_INTEGER               AppCompatFlags;                    /* 1d8/2c8 */
    ULARGE_INTEGER               AppCompatFlagsUser;                /* 1e0/2d0 */
    qemu_ptr                     ShimData;                          /* 1e8/2d8 */
    qemu_ptr                     AppCompatInfo;                     /* 1ec/2e0 */
    UNICODE_STRING32             CSDVersion;                        /* 1f0/2e8 */
    qemu_ptr                     ActivationContextData;             /* 1f8/2f8 */
    qemu_ptr                     ProcessAssemblyStorageMap;         /* 1fc/300 */
    qemu_ptr                     SystemDefaultActivationData;       /* 200/308 */
    qemu_ptr                     SystemAssemblyStorageMap;          /* 204/310 */
    qemu_handle                  MinimumStackCommit;                /* 208/318 */
    qemu_ptr                     FlsCallback;                       /* 20c/320 */
    LIST_ENTRY                   FlsListHead;                       /* 210/328 */
    qemu_ptr                     FlsBitmap;                         /* 218/338 */
    ULONG                        FlsBitmapBits[4];                  /* 21c/340 */
} PEB32, *PPEB32;

typedef struct tagRTL_BITMAP32 {
    ULONG       SizeOfBitMap; /* Number of bits in the bitmap */
    qemu_ptr    Buffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP32, *PRTL_BITMAP32;

struct qemu_ops
{
    uint64_t (*qemu_execute)(const void *code, uint64_t rcx);
    BOOL (*qemu_FreeLibrary)(HMODULE module);
    DWORD (*qemu_GetModuleFileName)(HMODULE module, WCHAR *filename, DWORD size);
    HMODULE (*qemu_GetModuleHandleEx)(DWORD flags, const WCHAR *name);
    const void *(*qemu_GetProcAddress)(HMODULE module, const char *name);
    void *(*qemu_getTEB)(void);
    TEB32 *(*qemu_getTEB32)(void);
    HMODULE (*qemu_LoadLibrary)(const WCHAR *name, DWORD flags);
    void (*qemu_set_except_handler)(uint64_t handler);
    void (*qemu_set_call_entry)(uint64_t call_entry);
    BOOL (*qemu_FindEntryForAddress)(void *addr, HMODULE *mod);
    BOOL (*qemu_DisableThreadLibraryCalls)(HMODULE mod);
    BOOL (*qemu_get_ldr_module)(HANDLE process, HMODULE mod, void **ldr);
    void *(*qemu_RtlPcToFileHeader)(void *pc, void **address);
    BOOL (*qemu_DllMain)(DWORD reason, void *reserved);
    NTSTATUS (*qemu_set_context)(HANDLE thread, void *ctx);
    HMODULE (*qemu_module_g2h)(uint64_t guest);
};

typedef void (*syscall_handler)(struct qemu_syscall *call);
typedef const syscall_handler *(WINAPI *syscall_lib_register)(const struct qemu_ops *ops, uint32_t *dll_num);

/* For now this is just a placeholder that is used to mark places where we're taking a guest pointer and
 * need a host pointer or vice versa. It has the practical purpose of shutting up the int to ptr conversion
 * warning. If we ever have a diverging address space this will probably call into qemu_ops. */
#define QEMU_G2H(a)((void *)(a))
#define QEMU_H2G(a)((uint64_t)(a))

#endif

#endif
