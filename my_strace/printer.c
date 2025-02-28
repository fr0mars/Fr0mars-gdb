#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "printer.h"

void print_short(short v)
{
    fprintf(stderr, "%hi", v);
}

void print_ushort(short v)
{
    fprintf(stderr, "%hu", v);
}

void print_int(int v)
{
    fprintf(stderr, "%d", v);
}

void print_uint(unsigned int v)
{
    fprintf(stderr, "%u", v);
}

void print_long(long v)
{
    fprintf(stderr, "%ld", v);
}

void print_ulong(unsigned long v)
{
    fprintf(stderr, "%lu", v);
}

static int print_labels(long v, struct label_t labels[], size_t size, int p)
{
    for (size_t i = 0; i < size; i++)
    {
        if (v & labels[i].mask)
        {
            if (p)
                fprintf(stderr, "|");

            fprintf(stderr, "%s", labels[i].name);
            p = 1;

            if (labels[i].mask == PROT_NONE)
                break;
        }
    }
    return p;
}

void print_oflags(int value)
{
    struct label_t oflags[] = {
        { O_CLOEXEC, "O_CLOEXEC" },
        { O_CREAT, "O_CREAT" },
        { O_EXCL, "O_EXCL" },
        { O_NOCTTY, "O_NOCTTY" },
        { O_TRUNC, "O_TRUNC" },
        { O_APPEND, "O_APPEND" },
        { O_NONBLOCK, "O_NONBLOCK" },
        { O_DSYNC, "O_DSYNC" },
        { O_SYNC, "O_SYNC" },
        { O_RSYNC, "O_RSYNC" }
    };

    int p = 1;
    if ((value & O_ACCMODE) == O_RDONLY)
        fprintf(stderr, "O_RDONLY");
    else if ((value & O_ACCMODE) == O_WRONLY)
        fprintf(stderr, "O_WRONLY");
    else if ((value & O_ACCMODE) == O_RDWR)
        fprintf(stderr, "O_RDWR");
    else
        p = 0;

    if (!print_labels(value, oflags, 10, p))
        fprintf(stderr, "0x%x", value);
}

void print_prot(long value)
{
    struct label_t prot_flags[] = {
        { PROT_NONE, "PROT_NONE" },
        { PROT_READ, "PROT_READ" },
        { PROT_WRITE, "PROT_WRITE" },
        { PROT_EXEC, "PROT_EXEC" },
    };

    if (!print_labels(value, prot_flags, 4, 0))
        fprintf(stderr, "0x%lx", value);

}

void print_flags(long value)
{
    struct label_t map_flags[] = {
        { MAP_SHARED, "MAP_SHARED" },
        { MAP_PRIVATE, "MAP_PRIVATE" },
        { MAP_32BIT, "MAP_32BIT" },
        { MAP_ANONYMOUS, "MAP_ANONYMOUS" },
        { MAP_DENYWRITE, "MAP_DENYWRITE" },
        { MAP_EXECUTABLE, "MAP_EXECUTABLE" },
        { MAP_FILE, "MAP_FILE" },
        { MAP_FIXED, "MAP_FIXED" },
        { MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE" },
        { MAP_GROWSDOWN, "MAP_GROWSDOWN" },
        { MAP_HUGETLB, "MAP_HUGETLB" },
        { MAP_LOCKED, "MAP_LOCKED" },
        { MAP_NONBLOCK, "MAP_NONBLOCK" },
        { MAP_NORESERVE, "MAP_NORESERVE" },
        { MAP_POPULATE, "MAP_POPULATE" },
        { MAP_STACK, "MAP_STACK" },
        { MAP_SYNC, "MAP_SYNC" },
    };
    print_labels(value, map_flags, 17, 0);
}

void print_fd(int value)
{
    if (value == AT_FDCWD)
        fprintf(stderr, "AT_FDCWD");
    else
        fprintf(stderr, "%d", value);
}

void print_buffer(char *buffer)
{
    if (buffer)
        fprintf(stderr, "\"%s\"", buffer);
    else
        fprintf(stderr, "NULL");
}

void print_ptr(long value)
{
    fprintf(stderr, "0x%lx", value);
}

void print_mode(int value)
{
    struct label_t modes[] = {
        { R_OK, "R_OK" },
        { W_OK, "W_OK" },
        { X_OK, "X_OK" },
        { F_OK, "F_OK" }
    };
    if (!print_labels(value, modes, 4, 0))
        fprintf(stderr, "%o", value);
}
