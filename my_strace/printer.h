#ifndef MY_STRACE_PRINTER_H
#define MY_STRACE_PRINTER_H

struct label_t
{
    long mask;
    const char *name;
};

void print_short(short v);
void print_ushort(short v);
void print_int(int v);
void print_uint(unsigned int v);
void print_long(long v);
void print_ulong(unsigned long v);
void print_oflags(int value);
void print_prot(long value);
void print_flags(long value);
void print_fd(int value);
void print_buffer(char *buffer);
void print_ptr(long value);
void print_mode(int value);

#endif /* !MY_STRACE_PRINTER_H */
