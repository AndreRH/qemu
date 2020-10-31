/* common syscall defines for all architectures */

/* Note: although the syscall numbers change between architectures,
   most of them stay the same, so we handle it by putting ifdefs if
   necessary */

#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#define TARGET_SIGHUP		 1
#define TARGET_SIGINT		 2
#define TARGET_SIGQUIT		 3
#define TARGET_SIGILL		 4
#define TARGET_SIGTRAP		 5
#define TARGET_SIGABRT		 6
#define TARGET_SIGIOT		 6
#define TARGET_SIGBUS		 7
#define TARGET_SIGFPE		 8
#define TARGET_SIGKILL		 9
#define TARGET_SIGUSR1		10
#define TARGET_SIGSEGV		11
#define TARGET_SIGUSR2		12
#define TARGET_SIGPIPE		13
#define TARGET_SIGALRM		14
#define TARGET_SIGTERM		15
#define TARGET_SIGSTKFLT	16
#define TARGET_SIGCHLD		17
#define TARGET_SIGCONT		18
#define TARGET_SIGSTOP		19
#define TARGET_SIGTSTP		20
#define TARGET_SIGTTIN		21
#define TARGET_SIGTTOU		22
#define TARGET_SIGURG		23
#define TARGET_SIGXCPU		24
#define TARGET_SIGXFSZ		25
#define TARGET_SIGVTALRM	26
#define TARGET_SIGPROF		27
#define TARGET_SIGWINCH     28
#define TARGET_SIGIO		29
#define TARGET_SIGPWR		30
#define TARGET_SIGSYS		31
#define TARGET_SIGRTMIN     32

#endif
