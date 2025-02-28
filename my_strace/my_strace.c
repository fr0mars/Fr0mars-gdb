#define _POSIX_C_SOURCE 200809L
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "printer.h"
#include "syscalls.h"

const struct syscall_t syscalls[512] = {
    [0] = { LONG, "read", 3, { { FD, "fd" }, { BUFFER, "buf" }, { UNSIGNED_LONG, "count" } } },
    [1] = { LONG, "write", 3, { { FD, "fd" }, { BUFFER, "buf" }, { UNSIGNED_LONG, "count" } } },
    [2] = { INT, "open", 3, { { BUFFER, "filename" }, { OFLAGS, "flags" }, { MODE, "mode" } } },
    [3] = { INT, "close", 1, { { FD, "fd" } } },
    [4] = { INT, "stat", 2, { { BUFFER, "filename" }, { POINTER, "statbuf" } } },
    [5] = { INT, "fstat", 2, { { FD, "fd" }, { POINTER, "statbuf" } } },
    [6] = { INT, "lstat", 2, { { BUFFER, "filename" }, { POINTER, "statbuf" } } },
    [7] = { INT, "poll", 3, { { POINTER, "ufds" }, { UNSIGNED_INT, "nfds" }, { LONG, "timeout_msecs" } } },
    [8] = { INT, "lseek", 3, { { FD, "fd" }, { INT, "offset" }, { UNSIGNED_INT, "origin" } } },
    [9] = { LONG, "mmap", 6, { { POINTER, "addr" }, { UNSIGNED_LONG, "len" }, { PROT, "prot" }, { FLAGS, "flags" }, { FD, "fd" }, { UNSIGNED_LONG, "off" } } },
    [10] = { INT, "mprotect", 3, { { POINTER, "start" }, { UNSIGNED_LONG, "len" }, { PROT, "prot" } } },
    [11] = { INT, "munmap", 2, { { POINTER, "addr" }, { UNSIGNED_LONG, "len" } } },
    [12] = { UNSIGNED_LONG, "brk", 1, { { POINTER, "addr" } } },
    [13] = { INT, "rt_sigaction", 4, { { INT, "sig" }, { POINTER, "act" }, { POINTER, "oact" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [14] = { INT, "rt_sigprocmask", 4, { { INT, "how" }, { POINTER, "nset" }, { POINTER, "oset" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [15] = { INT, "rt_sigreturn", 1, { { UNSIGNED_LONG, "__unused" } } },
    [16] = { INT, "ioctl", 3, { { FD, "fd" }, { UNSIGNED_INT, "cmd" }, { UNSIGNED_LONG, "arg" } } },
    [17] = { LONG, "pread64", 4, { { FD, "fd" }, { BUFFER, "buf" }, { UNSIGNED_LONG, "count" }, { LONG, "pos" } } },
    [18] = { LONG, "pwrite64", 4, { { FD, "fd" }, { BUFFER, "buf" }, { UNSIGNED_LONG, "count" }, { LONG, "pos" } } },
    [19] = { LONG, "readv", 3, { { FD, "fd" }, { POINTER, "vec" }, { UNSIGNED_LONG, "vlen" } } },
    [20] = { LONG, "writev", 3, { { FD, "fd" }, { POINTER, "vec" }, { UNSIGNED_LONG, "vlen" } } },
    [21] = { INT, "access", 2, { { BUFFER, "filename" }, { MODE, "mode" } } },
    [22] = { STRUCT, "pipe", 1, { { POINTER, "filedes" } } },
    [23] = { INT, "select", 5, { { INT, "n" }, { POINTER, "inp" }, { POINTER, "outp" }, { POINTER, "exp" }, { POINTER, "tvp" } } },
    [24] = { INT, "sched_yield", 0, { { 0 } } },
    [25] = { POINTER, "mremap", 5, { { POINTER, "addr" }, { UNSIGNED_LONG, "old_len" }, { UNSIGNED_LONG, "new_len" }, { FLAGS, "flags" }, { POINTER, "new_addr" }
 } },
    [26] = { INT, "msync", 3, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "len" }, { FLAGS, "flags" } } },
    [27] = { INT, "mincore", 3, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "len" }, { POINTER, "vec" } } },
    [28] = { INT, "madvise", 3, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "len_in" }, { INT, "behavior" } } },
    [29] = { INT, "shmget", 3, { { INT, "key" }, { UNSIGNED_LONG, "size" }, { INT, "shmflg" } } },
    [30] = { LONG, "shmat", 3, { { INT, "shmid" }, { BUFFER, "shmaddr" }, { INT, "shmflg" } } },
    [31] = { INT, "shmctl", 3, { { INT, "shmid" }, { INT, "cmd" }, { POINTER, "buf" } } },
    [32] = { INT, "dup", 1, { { UNSIGNED_INT, "fildes" } } },
    [33] = { INT, "dup2", 2, { { UNSIGNED_INT, "oldfd" }, { UNSIGNED_INT, "newfd" } } },
    [34] = { INT, "pause", 0, { { 0 } } },
    [35] = { INT, "nanosleep", 2, { { POINTER, "rqtp" }, { POINTER, "rmtp" } } },
    [36] = { INT, "getitimer", 2, { { INT, "which" }, { POINTER, "value" } } },
    [37] = { UNSIGNED_INT, "alarm", 1, { { UNSIGNED_INT, "seconds" } } },
    [38] = { INT, "setitimer", 3, { { INT, "which" }, { POINTER, "value" }, { POINTER, "ovalue" } } },
    [39] = { INT, "getpid", 0, { { 0 } } },
    [40] = { LONG, "sendfile", 4, { { INT, "out_fd" }, { INT, "in_fd" }, { POINTER, "offset" }, { UNSIGNED_LONG, "count" } } },
    [41] = { INT, "socket", 3, { { INT, "family" }, { INT, "type" }, { INT, "protocol" } } },
    [42] = { INT, "connect", 3, { { FD, "fd" }, { POINTER, "uservaddr" }, { INT, "addrlen" } } },
    [43] = { INT, "accept", 3, { { FD, "fd" }, { POINTER, "upeer_sockaddr" }, { POINTER, "upeer_addrlen" } } },
    [44] = { LONG, "sendto", 6, { { FD, "fd" }, { POINTER, "buff" }, { UNSIGNED_LONG, "len" }, { FLAGS, "flags" }, { POINTER, "addr" }, { INT, "addr_len" } } },
    [45] = { LONG, "recvfrom", 6, { { FD, "fd" }, { POINTER, "ubuf" }, { UNSIGNED_LONG, "size" }, { FLAGS, "flags" }, { POINTER, "addr" }, { POINTER, "addr_len" } } },
    [46] = { LONG, "sendmsg", 3, { { FD, "fd" }, { POINTER, "msg" }, { FLAGS, "flags" } } },
    [47] = { LONG, "recvmsg", 3, { { FD, "fd" }, { POINTER, "msg" }, { FLAGS, "flags" } } },
    [48] = { INT, "shutdown", 2, { { FD, "fd" }, { INT, "how" } } },
    [49] = { INT, "bind", 3, { { FD, "fd" }, { POINTER, "umyaddr" }, { INT, "addrlen" } } },
    [50] = { INT, "listen", 2, { { FD, "fd" }, { INT, "backlog" } } },
    [51] = { INT, "getsockname", 3, { { FD, "fd" }, { POINTER, "usockaddr" }, { POINTER, "usockaddr_len" } } },
    [52] = { INT, "getpeername", 3, { { FD, "fd" }, { POINTER, "usockaddr" }, { POINTER, "usockaddr_len" } } },
    [53] = { INT, "socketpair", 4, { { INT, "family" }, { INT, "type" }, { INT, "protocol" }, { POINTER, "usockvec" } } },
    [54] = { INT, "setsockopt", 5, { { FD, "fd" }, { INT, "level" }, { INT, "optname" }, { BUFFER, "optval" }, { INT, "optlen" } } },
    [55] = { INT, "getsockopt", 5, { { FD, "fd" }, { INT, "level" }, { INT, "optname" }, { BUFFER, "optval" }, { POINTER, "optlen" } } },
    [56] = { INT, "clone", 5, { { UNSIGNED_LONG, "clone_flags" }, { UNSIGNED_LONG, "newsp" }, { POINTER, "parent_tid" }, { POINTER, "child_tid" }, { UNSIGNED_INT, "tid" } } },
    [57] = { INT, "fork", 0, { { 0 } } },
    [58] = { INT, "vfork", 0, { { 0 } } },
    [59] = { INT, "execve", 3, { { BUFFER, "filename" }, { POINTER, "argv" }, { POINTER, "envp" } } },
    [60] = { VOID, "exit", 1, { { INT, "error_code" } } },
    [61] = { INT, "wait4", 4, { { INT, "upid" }, { POINTER, "stat_addr" }, { INT, "options" }, { POINTER, "ru" } } },
    [62] = { INT, "kill", 2, { { INT, "pid" }, { INT, "sig" } } },
    [63] = { INT, "uname", 1, { { POINTER, "name" } } },
    [64] = { INT, "semget", 3, { { INT, "key" }, { INT, "nsems" }, { INT, "semflg" } } },
    [65] = { INT, "semop", 3, { { INT, "semid" }, { POINTER, "tsops" }, { UNSIGNED_INT, "nsops" } } },
    [66] = { INT, "semctl", 4, { { INT, "semid" }, { INT, "semnum" }, { INT, "cmd" }, { UNION, "arg" } } },
    [67] = { INT, "shmdt", 1, { { BUFFER, "shmaddr" } } },
    [68] = { INT, "msgget", 2, { { INT, "key" }, { INT, "msgflg" } } },
    [69] = { INT, "msgsnd", 4, { { INT, "msqid" }, { POINTER, "msgp" }, { UNSIGNED_LONG, "msgsz" }, { INT, "msgflg" } } },
    [70] = { LONG, "msgrcv", 5, { { INT, "msqid" }, { POINTER, "msgp" }, { UNSIGNED_LONG, "msgsz" }, { LONG, "msgtyp" }, { INT, "msgflg" } } },
    [71] = { INT, "msgctl", 3, { { INT, "msqid" }, { INT, "cmd" }, { POINTER, "buf" } } },
    [72] = { INT, "fcntl", 3, { { FD, "fd" }, { UNSIGNED_INT, "cmd" }, { UNSIGNED_LONG, "arg" } } },
    [73] = { INT, "flock", 2, { { FD, "fd" }, { UNSIGNED_INT, "cmd" } } },
    [74] = { INT, "fsync", 1, { { FD, "fd" } } },
    [75] = { INT, "fdatasync", 1, { { FD, "fd" } } },
    [76] = { INT, "truncate", 2, { { BUFFER, "path" }, { LONG, "length" } } },
    [77] = { INT, "ftruncate", 2, { { FD, "fd" }, { UNSIGNED_LONG, "length" } } },
    [78] = { LONG, "getdents", 3, { { FD, "fd" }, { POINTER, "dirent" }, { UNSIGNED_INT, "count" } } },
    [79] = { BUFFER, "getcwd", 2, { { BUFFER, "buf" }, { UNSIGNED_LONG, "size" } } },
    [80] = { INT, "chdir", 1, { { BUFFER, "filename" } } },
    [81] = { INT, "fchdir", 1, { { FD, "fd" } } },
    [82] = { INT, "rename", 2, { { BUFFER, "oldname" }, { BUFFER, "newname" } } },
    [83] = { INT, "mkdir", 2, { { BUFFER, "pathname" }, { MODE, "mode" } } },
    [84] = { INT, "rmdir", 1, { { BUFFER, "pathname" } } },
    [85] = { INT, "creat", 2, { { BUFFER, "pathname" }, { MODE, "mode" } } },
    [86] = { INT, "link", 2, { { BUFFER, "oldname" }, { BUFFER, "newname" } } },
    [87] = { INT, "unlink", 1, { { BUFFER, "pathname" } } },
    [88] = { INT, "symlink", 2, { { BUFFER, "oldname" }, { BUFFER, "newname" } } },
    [89] = { LONG, "readlink", 3, { { BUFFER, "path" }, { BUFFER, "buf" }, { INT, "bufsiz" } } },
    [90] = { INT, "chmod", 2, { { BUFFER, "filename" }, { MODE, "mode" } } },
    [91] = { INT, "fchmod", 2, { { FD, "fd" }, { MODE, "mode" } } },
    [92] = { INT, "chown", 3, { { BUFFER, "filename" }, { UNSIGNED_INT, "user" }, { UNSIGNED_INT, "group" } } },
    [93] = { INT, "fchown", 3, { { FD, "fd" }, { UNSIGNED_INT, "user" }, { UNSIGNED_INT, "group" } } },
    [94] = { INT, "lchown", 3, { { BUFFER, "filename" }, { UNSIGNED_INT, "user" }, { UNSIGNED_INT, "group" } } },
    [95] = { MODE, "umask", 1, { { INT, "mask" } } },
    [96] = { INT, "gettimeofday", 2, { { POINTER, "tv" }, { POINTER, "tz" } } },
    [97] = { INT, "getrlimit", 2, { { UNSIGNED_INT, "resource" }, { POINTER, "rlim" } } },
    [98] = { INT, "getrusage", 2, { { INT, "who" }, { POINTER, "ru" } } },
    [99] = { INT, "sysinfo", 1, { { POINTER, "info" } } },
    [100] = { UNSIGNED_LONG, "times", 1, { { POINTER, "tbuf" } } },
    [101] = { LONG, "ptrace", 4, { { LONG, "request" }, { LONG, "pid" }, { POINTER, "addr" }, { UNSIGNED_LONG, "data" } } },
    [102] = { UNSIGNED_INT, "getuid", 0, { { 0 } } },
    [103] = { INT, "syslog", 3, { { INT, "type" }, { BUFFER, "buf" }, { INT, "len" } } },
    [104] = { UNSIGNED_INT, "getgid", 0, { { 0 } } },
    [105] = { INT, "setuid", 1, { { UNSIGNED_INT, "uid" } } },
    [106] = { INT, "setgid", 1, { { UNSIGNED_INT, "gid" } } },
    [107] = { UNSIGNED_INT, "geteuid", 0, { { 0 } } },
    [108] = { UNSIGNED_INT, "getegid", 0, { { 0 } } },
    [109] = { INT, "setpgid", 2, { { INT, "pid" }, { INT, "pgid" } } },
    [110] = { INT, "getppid", 0, { { 0 } } },
    [111] = { INT, "getpgrp", 0, { { 0 } } },
    [112] = { INT, "setsid", 0, { { 0 } } },
    [113] = { INT, "setreuid", 2, { { UNSIGNED_INT, "ruid" }, { UNSIGNED_INT, "euid" } } },
    [114] = { INT, "setregid", 2, { { UNSIGNED_INT, "rgid" }, { UNSIGNED_INT, "egid" } } },
    [115] = { INT, "getgroups", 2, { { INT, "gidsetsize" }, { POINTER, "grouplist" } } },
    [116] = { INT, "setgroups", 2, { { INT, "gidsetsize" }, { POINTER, "grouplist" } } },
    [117] = { INT, "setresuid", 3, { { POINTER, "ruid" }, { POINTER, "euid" }, { POINTER, "suid" } } },
    [118] = { INT, "getresuid", 3, { { POINTER, "ruid" }, { POINTER, "euid" }, { POINTER, "suid" } } },
    [119] = { INT, "setresgid", 3, { { UNSIGNED_INT, "rgid" }, { UNSIGNED_INT, "egid" }, { UNSIGNED_INT, "sgid" } } },
    [120] = { INT, "getresgid", 3, { { POINTER, "rgid" }, { POINTER, "egid" }, { POINTER, "sgid" } } },
    [121] = { INT, "getpgid", 1, { { INT, "pid" } } },
    [122] = { INT, "setfsuid", 1, { { UNSIGNED_INT, "uid" } } },
    [123] = { INT, "setfsgid", 1, { { UNSIGNED_INT, "gid" } } },
    [124] = { INT, "getsid", 1, { { INT, "pid" } } },
    [125] = { INT, "capget", 2, { { POINTER, "header" }, { POINTER, "dataptr" } } },
    [126] = { INT, "capset", 2, { { POINTER, "header" }, { POINTER, "data" } } },
    [127] = { INT, "rt_sigpending", 2, { { POINTER, "set" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [128] = { INT, "rt_sigtimedwait", 4, { { POINTER, "uthese" }, { POINTER, "uinfo" }, { POINTER, "uts" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [129] = { INT, "rt_sigqueueinfo", 3, { { INT, "pid" }, { INT, "sig" }, { POINTER, "uinfo" } } },
    [130] = { INT, "rt_sigsuspend", 2, { { POINTER, "unewset" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [131] = { INT, "sigaltstack", 2, { { POINTER, "uss" }, { POINTER, "uoss" } } },
    [132] = { INT, "utime", 2, { { BUFFER, "filename" }, { POINTER, "times" } } },
    [133] = { INT, "mknod", 3, { { BUFFER, "filename" }, { MODE, "mode" }, { UNSIGNED_INT, "dev" } } },
    [134] = { INT, "uselib", 0, { { 0 } } },
    [135] = { INT, "personality", 1, { { UNSIGNED_INT, "personality" } } },
    [136] = { INT, "ustat", 2, { { UNSIGNED_INT, "dev" }, { POINTER, "ubuf" } } },
    [137] = { INT, "statfs", 2, { { BUFFER, "pathname" }, { POINTER, "buf" } } },
    [138] = { INT, "fstatfs", 2, { { FD, "fd" }, { POINTER, "buf" } } },
    [139] = { INT, "sysfs", 3, { { INT, "option" }, { UNSIGNED_LONG, "arg1" }, { UNSIGNED_LONG, "arg2" } } },
    [140] = { INT, "getpriority", 2, { { INT, "which" }, { INT, "who" } } },
    [141] = { INT, "setpriority", 3, { { INT, "which" }, { INT, "who" }, { INT, "niceval" } } },
    [142] = { INT, "sched_setparam", 2, { { INT, "pid" }, { POINTER, "param" } } },
    [143] = { INT, "sched_getparam", 2, { { INT, "pid" }, { POINTER, "param" } } },
    [144] = { INT, "sched_setscheduler", 3, { { INT, "pid" }, { INT, "policy" }, { POINTER, "param" } } },
    [145] = { INT, "sched_getscheduler", 1, { { INT, "pid" } } },
    [146] = { INT, "sched_get_priority_max", 1, { { INT, "policy" } } },
    [147] = { INT, "sched_get_priority_min", 1, { { INT, "policy" } } },
    [148] = { INT, "sched_rr_get_interval", 2, { { INT, "pid" }, { POINTER, "interval" } } },
    [149] = { INT, "mlock", 2, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "len" } } },
    [150] = { INT, "munlock", 2, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "len" } } },
    [151] = { INT, "mlockall", 1, { { FLAGS, "flags" } } },
    [152] = { INT, "munlockall", 0, { { 0 } } },
    [153] = { INT, "vhangup", 0, { { 0 } } },
    [154] = { INT, "modify_ldt", 3, { { INT, "func" }, { POINTER, "ptr" }, { UNSIGNED_LONG, "bytecount" } } },
    [155] = { INT, "pivot_root", 2, { { BUFFER, "new_root" }, { BUFFER, "put_old" } } },
    [156] = { INT, "_sysctl", 1, { { POINTER, "args" } } },
    [157] = { INT, "prctl", 5, { { INT, "option" }, { UNSIGNED_LONG, "arg2" }, { UNSIGNED_LONG, "arg3" }, { UNSIGNED_LONG, "arg4" }, { UNSIGNED_LONG, "arg5" } } },
    [158] = { INT, "arch_prctl", 2, { { INT, "code" }, { POINTER, "addr" } } },
    [159] = { INT, "adjtimex", 1, { { POINTER, "txc_p" } } },
    [160] = { INT, "setrlimit", 2, { { UNSIGNED_INT, "resource" }, { POINTER, "rlim" } } },
    [161] = { INT, "chroot", 1, { { BUFFER, "filename" } } },
    [162] = { VOID, "sync", 0, { { 0 } } },
    [163] = { INT, "acct", 1, { { BUFFER, "name" } } },
    [164] = { INT, "settimeofday", 2, { { POINTER, "tv" }, { POINTER, "tz" } } },
    [165] = { INT, "mount", 5, { { BUFFER, "dev_name" }, { BUFFER, "dir_name" }, { BUFFER, "type" }, { FLAGS, "flags" }, { POINTER, "data" } } },
    [166] = { INT, "umount2", 2, { { BUFFER, "target" }, { FLAGS, "flags" } } },
    [167] = { INT, "swapon", 2, { { BUFFER, "specialfile" }, { INT, "swap_flags" } } },
    [168] = { INT, "swapoff", 1, { { BUFFER, "specialfile" } } },
    [169] = { INT, "reboot", 4, { { INT, "magic1" }, { INT, "magic2" }, { UNSIGNED_INT, "cmd" }, { POINTER, "arg" } } },
    [170] = { INT, "sethostname", 2, { { BUFFER, "name" }, { INT, "len" } } },
    [171] = { INT, "setdomainname", 2, { { BUFFER, "name" }, { INT, "len" } } },
    [172] = { INT, "iopl", 2, { { UNSIGNED_INT, "level" }, { POINTER, "regs" } } },
    [173] = { INT, "ioperm", 3, { { UNSIGNED_LONG, "from" }, { UNSIGNED_LONG, "num" }, { INT, "turn_on" } } },
    [174] = { BUFFER, "create_module", 0, { { 0 } } },
    [175] = { INT, "init_module", 3, { { POINTER, "umod" }, { UNSIGNED_LONG, "len" }, { BUFFER, "uargs" } } },
    [176] = { INT, "delete_module", 2, { { POINTER, "name_user" }, { FLAGS, "flags" } } },
    [177] = { INT, "get_kernel_syms", 0, { { 0 } } },
    [178] = { INT, "query_module", 0, { { 0 } } },
    [179] = { INT, "quotactl", 4, { { UNSIGNED_INT, "cmd" }, { BUFFER, "special" }, { UNSIGNED_INT, "id" }, { POINTER, "addr" } } },
    [180] = { LONG, "nfsservctl", 0, { { 0 } } },
    [181] = { VOID, "getpmsg", 0, { { 0 } } },
    [182] = { VOID, "putpmsg", 0, { { 0 } } },
    [183] = { VOID, "afs_syscall", 0, { { 0 } } },
    [184] = { VOID, "tuxcall", 0, { { 0 } } },
    [185] = { VOID, "security", 0, { { 0 } } },
    [186] = { INT, "gettid", 0, { { 0 } } },
    [187] = { LONG, "readahead", 3, { { FD, "fd" }, { LONG, "offset" }, { UNSIGNED_LONG, "count" } } },
    [188] = { INT, "setxattr", 5, { { BUFFER, "pathname" }, { BUFFER, "name" }, { POINTER, "value" }, { UNSIGNED_LONG, "size" }, { FLAGS, "flags" } } },
    [189] = { INT, "lsetxattr", 5, { { BUFFER, "pathname" }, { BUFFER, "name" }, { POINTER, "value" }, { UNSIGNED_LONG, "size" }, { FLAGS, "flags" } } },
    [190] = { INT, "fsetxattr", 5, { { FD, "fd" }, { BUFFER, "name" }, { POINTER, "value" }, { UNSIGNED_LONG, "size" }, { FLAGS, "flags" } } },
    [191] = { LONG, "getxattr", 4, { { BUFFER, "pathname" }, { BUFFER, "name" }, { POINTER, "value" }, { UNSIGNED_LONG, "size" } } },
    [192] = { LONG, "lgetxattr", 4, { { BUFFER, "pathname" }, { BUFFER, "name" }, { POINTER, "value" }, { UNSIGNED_LONG, "size" } } },
    [193] = { LONG, "fgetxattr", 4, { { FD, "fd" }, { POINTER, "name" }, { POINTER, "value" }, { UNSIGNED_LONG, "size" } } },
    [194] = { LONG, "listxattr", 3, { { BUFFER, "pathname" }, { BUFFER, "list" }, { UNSIGNED_LONG, "size" } } },
    [195] = { LONG, "llistxattr", 3, { { BUFFER, "pathname" }, { BUFFER, "list" }, { UNSIGNED_LONG, "size" } } },
    [196] = { LONG, "flistxattr", 3, { { FD, "fd" }, { BUFFER, "list" }, { UNSIGNED_LONG, "size" } } },
    [197] = { INT, "removexattr", 2, { { BUFFER, "pathname" }, { BUFFER, "name" } } },
    [198] = { INT, "lremovexattr", 2, { { BUFFER, "pathname" }, { BUFFER, "name" } } },
    [199] = { INT, "fremovexattr", 2, { { FD, "fd" }, { BUFFER, "name" } } },
    [200] = { INT, "tkill", 2, { { INT, "pid" }, { INT, "sig" } } },
    [201] = { UNSIGNED_LONG, "time", 1, { { POINTER, "tloc" } } },
    [202] = { LONG, "futex", 6, { { POINTER, "uaddr" }, { INT, "op" }, { INT, "val" }, { POINTER, "utime" }, { POINTER, "uaddr2" }, { INT, "val3" } } },
    [203] = { INT, "sched_setaffinity", 3, { { INT, "pid" }, { UNSIGNED_INT, "len" }, { POINTER, "user_mask_ptr" } } },
    [204] = { INT, "sched_getaffinity", 3, { { INT, "pid" }, { UNSIGNED_INT, "len" }, { POINTER, "user_mask_ptr" } } },
    [205] = { INT, "set_thread_area", 0, { { 0 } } },
    [206] = { LONG, "io_setup", 2, { { UNSIGNED_INT, "nr_events" }, { POINTER, "ctxp" } } },
    [207] = { INT, "io_destroy", 1, { { UNSIGNED_LONG, "ctx" } } },
    [208] = { INT, "io_getevents", 4, { { UNSIGNED_LONG, "ctx_id" }, { LONG, "min_nr" }, { LONG, "nr" }, { POINTER, "events" } } },
    [209] = { INT, "io_submit", 3, { { UNSIGNED_LONG, "ctx_id" }, { LONG, "nr" }, { POINTER, "iocbpp" } } },
    [210] = { INT, "io_cancel", 3, { { UNSIGNED_LONG, "ctx_id" }, { POINTER, "iocb" }, { POINTER, "result" } } },
    [211] = { INT, "get_thread_area", 0, { { 0 } } },
    [212] = { INT, "lookup_dcookie", 3, { { UNSIGNED_LONG, "cookie64" }, { LONG, "buf" }, { LONG, "len" } } },
    [213] = { INT, "epoll_create", 1, { { INT, "size" } } },
    [214] = { INT, "epoll_ctl_old", 0, { { 0 } } },
    [215] = { INT, "epoll_wait_old", 0, { { 0 } } },
    [216] = { INT, "remap_file_pages", 5, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "size" }, { PROT, "prot" }, { UNSIGNED_LONG, "pgoff" }, { FLAGS, "flags" } } },
    [217] = { LONG, "getdents64", 3, { { FD, "fd" }, { POINTER, "dirent" }, { UNSIGNED_INT, "count" } } },
    [218] = { INT, "set_tid_address", 1, { { POINTER, "tidptr" } } },
    [219] = { LONG, "restart_syscall", 0, { { 0 } } },
    [220] = { INT, "semtimedop", 4, { { INT, "semid" }, { POINTER, "tsops" }, { UNSIGNED_INT, "nsops" }, { POINTER, "timeout" } } },
    [221] = { INT, "fadvise64", 4, { { FD, "fd" }, { LONG, "offset" }, { UNSIGNED_LONG, "len" }, { INT, "advice" } } },
    [222] = { INT, "timer_create", 3, { { INT, "which_clock" }, { POINTER, "timer_event_spec" }, { POINTER, "created_timer_id" } } },
    [223] = { INT, "timer_settime", 4, { { INT, "timer_id" }, { FLAGS, "flags" }, { POINTER, "new_setting" }, { POINTER, "old_setting" } } },
    [224] = { INT, "timer_gettime", 2, { { INT, "timer_id" }, { POINTER, "setting" } } },
    [225] = { INT, "timer_getoverrun", 1, { { INT, "timer_id" } } },
    [226] = { INT, "timer_delete", 1, { { INT, "timer_id" } } },
    [227] = { INT, "clock_settime", 2, { { INT, "which_clock" }, { POINTER, "tp" } } },
    [228] = { INT, "clock_gettime", 2, { { INT, "which_clock" }, { POINTER, "tp" } } },
    [229] = { INT, "clock_getres", 2, { { INT, "which_clock" }, { POINTER, "tp" } } },
    [230] = { INT, "clock_nanosleep", 4, { { INT, "which_clock" }, { FLAGS, "flags" }, { POINTER, "rqtp" }, { POINTER, "rmtp" } } },
    [231] = { VOID, "exit_group", 1, { { INT, "error_code" } } },
    [232] = { INT, "epoll_wait", 4, { { INT, "epfd" }, { POINTER, "events" }, { INT, "maxevents" }, { INT, "timeout" } } },
    [233] = { INT, "epoll_ctl", 4, { { INT, "epfd" }, { INT, "op" }, { FD, "fd" }, { POINTER, "event" } } },
    [234] = { INT, "tgkill", 3, { { INT, "tgid" }, { INT, "pid" }, { INT, "sig" } } },
    [235] = { INT, "utimes", 2, { { BUFFER, "filename" }, { POINTER, "utimes" } } },
    [236] = { VOID, "vserver", 0, { { 0 } } },
    [237] = { LONG, "mbind", 6, { { UNSIGNED_LONG, "start" }, { UNSIGNED_LONG, "len" }, { MODE, "mode" }, { POINTER, "nmask" }, { UNSIGNED_LONG, "maxnode" }, { FLAGS, "flags" } } },
    [238] = { LONG, "set_mempolicy", 3, { { MODE, "mode" }, { POINTER, "nmask" }, { UNSIGNED_LONG, "maxnode" } } },
    [239] = { LONG, "get_mempolicy", 5, { { POINTER, "policy" }, { POINTER, "nmask" }, { UNSIGNED_LONG, "maxnode" }, { POINTER, "addr" }, { FLAGS, "flags" } } },
    [240] = { INT, "mq_open", 4, { { BUFFER, "u_name" }, { INT, "oflag" }, { MODE, "mode" }, { POINTER, "u_attr" } } },
    [241] = { INT, "mq_unlink", 1, { { BUFFER, "u_name" } } },
    [242] = { INT, "mq_timedsend", 5, { { INT, "mqdes" }, { BUFFER, "u_msg_ptr" }, { UNSIGNED_LONG, "msg_len" }, { UNSIGNED_INT, "msg_prio" }, { POINTER, "u_abs_timeout" } }
 },
    [243] = { LONG, "mq_timedreceive", 5, { { INT, "mqdes" }, { BUFFER, "u_msg_ptr" }, { UNSIGNED_LONG, "msg_len" }, { POINTER, "u_msg_prio" }, { POINTER, "u_abs_timeout" } 
} },
    [244] = { INT, "mq_notify", 2, { { INT, "mqdes" }, { POINTER, "u_notification" } } },
    [245] = { INT, "mq_getsetattr", 3, { { INT, "mqdes" }, { POINTER, "u_mqstat" }, { POINTER, "u_omqstat" } } },
    [246] = { LONG, "kexec_load", 4, { { UNSIGNED_LONG, "entry" }, { UNSIGNED_LONG, "nr_segments" }, { POINTER, "segments" }, { FLAGS, "flags" } } },
    [247] = { INT, "waitid", 5, { { INT, "which" }, { INT, "upid" }, { POINTER, "infop" }, { INT, "options" }, { POINTER, "ru" } } },
    [248] = { INT, "add_key", 4, { { BUFFER, "_type" }, { BUFFER, "_description" }, { POINTER, "_payload" }, { UNSIGNED_LONG, "plen" } } },
    [249] = { INT, "request_key", 4, { { BUFFER, "_type" }, { BUFFER, "_description" }, { BUFFER, "_callout_info" }, { INT, "destringid" } } },
    [250] = { LONG, "keyctl", 5, { { INT, "option" }, { UNSIGNED_LONG, "arg2" }, { UNSIGNED_LONG, "arg3" }, { UNSIGNED_LONG, "arg4" }, { UNSIGNED_LONG, "arg5" } } },
    [251] = { INT, "ioprio_set", 3, { { INT, "which" }, { INT, "who" }, { INT, "ioprio" } } },
    [252] = { INT, "ioprio_get", 2, { { INT, "which" }, { INT, "who" } } },
    [253] = { INT, "inotify_init", 0, { { 0 } } },
    [254] = { INT, "inotify_add_watch", 3, { { FD, "fd" }, { BUFFER, "pathname" }, { INT, "mask" } } },
    [255] = { INT, "inotify_rm_watch", 2, { { FD, "fd" }, { INT, "wd" } } },
    [256] = { LONG, "migrate_pages", 4, { { INT, "pid" }, { UNSIGNED_LONG, "maxnode" }, { POINTER, "old_nodes" }, { POINTER, "new_nodes" } } },
    [257] = { INT, "openat", 3, { { FD, "dfd" }, { BUFFER, "filename" }, { OFLAGS, "flags" }, { MODE, "mode" } } },
    [258] = { INT, "mkdirat", 3, { { FD, "dfd" }, { BUFFER, "pathname" }, { MODE, "mode" } } },
    [259] = { INT, "mknodat", 4, { { FD, "dfd" }, { BUFFER, "filename" }, { MODE, "mode" }, { UNSIGNED_INT, "dev" } } },
    [260] = { INT, "fchownat", 5, { { FD, "dfd" }, { BUFFER, "filename" }, { UNSIGNED_INT, "user" }, { UNSIGNED_INT, "group" }, { INT, "flag" } } },
    [261] = { INT, "futimesat", 3, { { FD, "dfd" }, { BUFFER, "filename" }, { POINTER, "utimes" } } },
    [262] = { INT, "newfstatat", 4, { { FD, "dfd" }, { BUFFER, "filename" }, { POINTER, "statbuf" }, { INT, "flag" } } },
    [263] = { INT, "unlinkat", 3, { { FD, "dfd" }, { BUFFER, "pathname" }, { INT, "flag" } } },
    [264] = { INT, "renameat", 4, { { FD, "oldfd" }, { BUFFER, "oldname" }, { INT, "newfd" }, { BUFFER, "newname" } } },
    [265] = { INT, "linkat", 5, { { FD, "oldfd" }, { BUFFER, "oldname" }, { INT, "newfd" }, { BUFFER, "newname" }, { FLAGS, "flags" } } },
    [266] = { INT, "symlinkat", 3, { { BUFFER, "oldname" }, { INT, "newfd" }, { BUFFER, "newname" } } },
    [267] = { LONG, "readlinkat", 4, { { INT, "dfd" }, { BUFFER, "pathname" }, { BUFFER, "buf" }, { INT, "bufsiz" } } },
    [268] = { INT, "fchmodat", 3, { { FD, "dfd" }, { BUFFER, "filename" }, { MODE, "mode" } } },
    [269] = { INT, "faccessat", 3, { { FD, "dfd" }, { BUFFER, "filename" }, { MODE, "mode" } } },
    [270] = { VOID, "pselect6", 6, { { INT, "n" }, { POINTER, "inp" }, { POINTER, "outp" }, { POINTER, "exp" }, { POINTER, "tsp" }, { POINTER, "sig" } } },
    [271] = { INT, "ppoll", 5, { { POINTER, "ufds" }, { UNSIGNED_INT, "nfds" }, { POINTER, "tsp" }, { POINTER, "sigmask" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [272] = { INT, "unshare", 1, { { UNSIGNED_LONG, "unshare_flags" } } },
    [273] = { LONG, "set_robust_list", 2, { { POINTER, "head" }, { UNSIGNED_LONG, "len" } } },
    [274] = { LONG, "get_robust_list", 3, { { INT, "pid" }, { POINTER, "head_ptr" }, { POINTER, "len_ptr" } } },
    [275] = { LONG, "splice", 6, { { FD, "fd_in" }, { POINTER, "off_in" }, { FD, "fd_out" }, { POINTER, "off_out" }, { UNSIGNED_LONG, "len" }, { FLAGS, "flags" } } },
    [276] = { LONG, "tee", 4, { { FD, "fdin" }, { FD, "fdout" }, { UNSIGNED_LONG, "len" }, { FLAGS, "flags" } } },
    [277] = { INT, "sync_file_range", 4, { { FD, "fd" }, { LONG, "offset" }, { LONG, "bytes" }, { FLAGS, "flags" } } },
    [278] = { LONG, "vmsplice", 4, { { FD, "fd" }, { POINTER, "iov" }, { UNSIGNED_LONG, "nr_segs" }, { FLAGS, "flags" } } },
    [279] = { LONG, "move_pages", 6, { { INT, "pid" }, { UNSIGNED_LONG, "nr_pages" }, { POINTER, "pages" }, { POINTER, "nodes" }, { POINTER, "status" }, { FLAGS, "flags" } }
 },
    [280] = { INT, "utimensat", 4, { { FD, "dfd" }, { BUFFER, "filename" }, { POINTER, "utimes" }, { FLAGS, "flags" } } },
    [281] = { INT, "epoll_pwait", 6, { { FD, "epfd" }, { POINTER, "events" }, { INT, "maxevents" }, { INT, "timeout" }, { POINTER, "sigmask" }, { UNSIGNED_LONG, "sigsetsize" } } },
    [282] = { INT, "signalfd", 3, { { FD, "ufd" }, { POINTER, "user_mask" }, { UNSIGNED_LONG, "sizemask" } } },
    [283] = { INT, "timerfd_create", 2, { { INT, "clockid" }, { FLAGS, "flags" } } },
    [284] = { INT, "eventfd", 1, { { UNSIGNED_INT, "count" } } },
    [285] = { INT, "fallocate", 4, { { FD, "fd" }, { MODE, "mode" }, { LONG, "offset" }, { LONG, "len" } } },
    [286] = { INT, "timerfd_settime", 4, { { FD, "ufd" }, { FLAGS, "flags" }, { POINTER, "utmr" }, { POINTER, "otmr" } } },
    [287] = { INT, "timerfd_gettime", 2, { { INT, "ufd" }, { POINTER, "otmr" } } },
    [288] = { INT, "accept4", 4, { { FD, "fd" }, { POINTER, "upeer_sockaddr" }, { POINTER, "upeer_addrlen" }, { FLAGS, "flags" } } },
    [289] = { INT, "signalfd4", 4, { { FD, "ufd" }, { POINTER, "user_mask" }, { UNSIGNED_LONG, "sizemask" }, { FLAGS, "flags" } } },
    [290] = { INT, "eventfd2", 2, { { UNSIGNED_INT, "count" }, { FLAGS, "flags" } } },
    [291] = { INT, "epoll_create1", 1, { { FLAGS, "flags" } } },
    [292] = { INT, "dup3", 3, { { FD, "oldfd" }, { FD, "newfd" }, { FLAGS, "flags" } } },
    [293] = { INT, "pipe2", 2, { { POINTER, "filedes" }, { FLAGS, "flags" } } },
    [294] = { INT, "inotify_init1", 1, { { FLAGS, "flags" } } },
    [295] = { LONG, "preadv", 5, { { FD, "fd" }, { POINTER, "vec" }, { UNSIGNED_LONG, "vlen" }, { UNSIGNED_LONG, "pos_l" }, { UNSIGNED_LONG, "pos_h" } } },
    [296] = { LONG, "pwritev", 5, { { FD, "fd" }, { POINTER, "vec" }, { UNSIGNED_LONG, "vlen" }, { UNSIGNED_LONG, "pos_l" }, { UNSIGNED_LONG, "pos_h" } } },
    [297] = { INT, "rt_tgsigqueueinfo", 4, { { INT, "tgid" }, { INT, "pid" }, { INT, "sig" }, { POINTER, "uinfo" } } },
    [298] = { INT, "perf_event_open", 5, { { POINTER, "attr_uptr" }, { INT, "pid" }, { INT, "cpu" }, { INT, "group_fd" }, { FLAGS, "flags" } } },
    [299] = { INT, "recvmmsg", 5, { { FD, "fd" }, { POINTER, "mmsg" }, { UNSIGNED_INT, "vlen" }, { FLAGS, "flags" }, { POINTER, "timeout" } } },
    [300] = { INT, "fanotify_init", 2, { { FLAGS, "flags" }, { UNSIGNED_INT, "event_f_flags" } } },
    [301] = { INT, "fanotify_mark", 5, { { LONG, "fanotify_fd" }, { FLAGS, "flags" }, { UNSIGNED_LONG, "mask" }, { FD, "dfd" }, { LONG, "pathname" } } },
    [302] = { INT, "prlimit64", 4, { { INT, "pid" }, { UNSIGNED_INT, "resource" }, { POINTER, "new_rlim" }, { POINTER, "old_rlim" } } },
    [303] = { INT, "name_to_handle_at", 5, { { INT, "dfd" }, { BUFFER, "name" }, { POINTER, "handle" }, { POINTER, "mnt_id" }, { INT, "flag" } } },
    [304] = { INT, "open_by_handle_at", 5, { { INT, "dfd" }, { BUFFER, "name" }, { POINTER, "handle" }, { POINTER, "mnt_id" }, { OFLAGS, "flags" } } },
    [305] = { INT, "clock_adjtime", 2, { { INT, "which_clock" }, { POINTER, "tx" } } },
    [306] = { INT, "syncfs", 1, { { FD, "fd" } } },
    [307] = { INT, "sendmmsg", 4, { { FD, "fd" }, { POINTER, "mmsg" }, { UNSIGNED_INT, "vlen" }, { FLAGS, "flags" } } },
    [308] = { INT, "setns", 2, { { FD, "fd" }, { INT, "nstype" } } },
    [309] = { INT, "getcpu", 3, { { POINTER, "cpup" }, { POINTER, "nodep" }, { POINTER, "unused" } } },
    [310] = { LONG, "process_vm_readv", 6, { { INT, "pid" }, { POINTER, "lvec" }, { UNSIGNED_LONG, "liovcnt" }, { POINTER, "rvec" }, { UNSIGNED_LONG, "riovcnt" }, { FLAGS, "flags" } } },
    [311] = { LONG, "process_vm_writev", 6, { { INT, "pid" }, { POINTER, "lvec" }, { UNSIGNED_LONG, "liovcnt" }, { POINTER, "rvec" }, { UNSIGNED_LONG, "riovcnt" }, { FLAGS, "flags" } } },
    [312] = { INT, "kcmp", 5, { { INT, "pid1" }, { INT, "pid2" }, { INT, "type" }, { UNSIGNED_LONG, "idx1" }, { UNSIGNED_LONG, "idx2" } } },
    [313] = { INT, "finit_module", 3, { { FD, "fd" }, { POINTER, "uargs" }, { FLAGS, "flags" } } },
    [314] = { INT, "sched_setattr", 3, { { INT, "pid" }, { POINTER, "attr" }, { FLAGS, "flags" } } },
    [315] = { INT, "sched_getattr", 4, { { INT, "pid" }, { POINTER, "attr" }, { UNSIGNED_INT, "size" }, { FLAGS, "flags" } } },
    [316] = { INT, "renameat2", 5, { { INT, "olddfd" }, { POINTER, "oldname" }, { INT, "newdfd" }, { POINTER, "newname" }, { FLAGS, "flags" } } },
    [317] = { INT, "seccomp", 3, { { UNSIGNED_INT, "op" }, { FLAGS, "flags" }, { POINTER, "uargs" } } }
};


char *read_string_from_child(pid_t pid, unsigned long long addr)
{
    char *str = malloc(256);
    if (!str)
        return NULL;

    long dw;
    int i = 0;
    while (i < 248)
    {
        dw = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (dw == -1)
        {
            free(str);
            return NULL;
        }
        memcpy(str + i, &dw, 8);
        if (memchr(&dw, '\0', sizeof(long)) != NULL)
            break;
        i += 8;
    }
    str[0xff] = '\0';
    return str;
}


void print_value(enum c_types type, unsigned long value, pid_t pid)
{
    switch (type)
    {
        case UNSIGNED_SHORT:
            print_ushort(value);
            break;
        case SHORT:
            print_short(value);
            break;
        case UNSIGNED_INT:
            print_uint(value);
            break;
        case INT:
            print_int(value);
            break;
        case UNSIGNED_LONG:
            print_ulong(value);
            break;
        case LONG:
            print_long(value);
            break;
        case POINTER:
            print_ptr(value);
            break;
        case BUFFER:
            print_buffer(read_string_from_child(pid, value));
            break;
        case OFLAGS:
            print_oflags(value);
            break;
        case FLAGS:
            print_flags(value);
            break;
        case FD:
            print_fd(value);
            break;
        case PROT:
            print_prot(value);
            break;
        case MODE:
            print_mode(value);
            break;
        case VOID:
        case STRUCT:
        case UNION:
            print_int(0);
            break;
    }
}


void print_args(struct user_regs_struct regs, pid_t pid)
{
    struct syscall_t cur = syscalls[regs.orig_rax];
    unsigned long long regs_args[] = { regs.rdi, regs.rsi, regs.rdx,
                                       regs.r10, regs.r8,  regs.r9 };
    fprintf(stderr, "%s(", cur.name);
    for (int i = 0; i < cur.nb_args; i++)
    {
        fprintf(stderr, "%s = ", cur.args[i].name);
        print_value(cur.args[i].type, regs_args[i], pid);

        if (i != cur.nb_args - 1)
            fprintf(stderr, ", ");
    }

    fprintf(stderr, ") = ");
}


void strace(pid_t pid, int argc, char **argv)
{
    int wstatus;
    int forbidden = 0;
    struct user_regs_struct regs;
    struct syscall_t syscall = { 0 };
    for (;;)
    {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &wstatus, 0);


        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (regs.orig_rax <= 317)
        {
            syscall = syscalls[regs.orig_rax];
            for (int i = 2; i < argc; i++)
            {
                if (strcmp(argv[i], syscall.name) == 0)
                {
                    regs.orig_rax = -1;
                    regs.rax = -1;
                    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    forbidden = 1;
                    break;
                }
            }
            if (!forbidden)
                print_args(regs, pid);

            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            waitpid(pid, &wstatus, 0);


            if (WIFEXITED(wstatus))
                break;

            if (!forbidden)
            {
                print_value(syscall.return_type, regs.rax, pid);
                fprintf(stderr, "\n");
            }
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return 1;

    else if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(argv[1], &argv[1], NULL);
        return 0;
    }
    strace(pid, argc, argv);
}
