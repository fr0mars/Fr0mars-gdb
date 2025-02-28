#ifndef MY_STRACE_UTILS_H
#define MY_STRACE_UTILS_H

enum c_types
{
    UNSIGNED_SHORT,
    SHORT,
    UNSIGNED_INT,
    INT,
    UNSIGNED_LONG,
    LONG,
    POINTER,
    BUFFER,
    OFLAGS,
    FLAGS,
    FD,
    PROT,
    MODE,
    VOID,
    STRUCT,
    UNION
};

struct arg_t
{
    enum c_types type;
    char *name;
};

struct syscall_t
{
    enum c_types return_type;
    char *name;
    int nb_args;
    struct arg_t args[6];
};

#endif /* !MY_STRACE_UTILS_H */
