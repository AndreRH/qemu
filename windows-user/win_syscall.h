#ifndef QEMU_WIN_SYSCALL_H
#define QEMU_WIN_SYSCALL_H

#include "windows-user-services.h"

BOOL load_host_dlls(BOOL load_msvcrt);
void do_syscall(struct qemu_syscall *call);
uint64_t qemu_execute(const void *code, uint64_t rcx);
BOOL qemu_DllMain(DWORD reason, void *reserved);

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

/***********************************************************************
 * TEB data structure
 */
typedef struct _TEB32
{                                                                 /* win32/win64 */
    NT_TIB32                     Tib;                               /* 000/0000 */
    qemu_ptr                        EnvironmentPointer;                /* 01c/0038 */
    CLIENT_ID                    ClientId;                          /* 020/0040 */
    qemu_ptr                        ActiveRpcHandle;                   /* 028/0050 */
    qemu_ptr                        ThreadLocalStoragePointer;         /* 02c/0058 */
    qemu_ptr                         Peb;                               /* 030/0060 */
    ULONG                        LastErrorValue;                    /* 034/0068 */
    ULONG                        CountOfOwnedCriticalSections;      /* 038/006c */
    qemu_ptr                        CsrClientThread;                   /* 03c/0070 */
    qemu_ptr                        Win32ThreadInfo;                   /* 040/0078 */
    ULONG                        Win32ClientInfo[31];               /* 044/0080 used for user32 private data in Wine */
    qemu_ptr                        WOW32Reserved;                     /* 0c0/0100 */
    ULONG                        CurrentLocale;                     /* 0c4/0108 */
    ULONG                        FpSoftwareStatusRegister;          /* 0c8/010c */
    qemu_ptr                        SystemReserved1[54];               /* 0cc/0110 used for kernel32 private data in Wine */
    LONG                         ExceptionCode;                     /* 1a4/02c0 */
    ACTIVATION_CONTEXT_STACK     ActivationContextStack;            /* 1a8/02c8 */
    BYTE                         SpareBytes1[24];                   /* 1bc/02e8 */
    qemu_ptr                        SystemReserved2[10];               /* 1d4/0300 used for ntdll platform-specific private data in Wine */
    GDI_TEB_BATCH                GdiTebBatch;                       /* 1fc/0350 used for ntdll private data in Wine */
    qemu_handle                       gdiRgn;                            /* 6dc/0838 */
    qemu_handle                       gdiPen;                            /* 6e0/0840 */
    qemu_handle                       gdiBrush;                          /* 6e4/0848 */
    CLIENT_ID                    RealClientId;                      /* 6e8/0850 */
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
    UNICODE_STRING               StaticUnicodeString;               /* bf8/1258 used by advapi32 */
    WCHAR                        StaticUnicodeBuffer[261];          /* c00/1268 used by advapi32 */
    qemu_ptr                        DeallocationStack;                 /* e0c/1478 */
    qemu_ptr                        TlsSlots[64];                      /* e10/1480 */
    LIST_ENTRY                   TlsLinks;                          /* f10/1680 */
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

#endif
