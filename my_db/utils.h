#pragma once

#define _POSIX_C_SOURCE 200809L

#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct bp
{
    size_t address;
    long data;
    char *name;
};

struct linked_list
{
    struct bp data;
    struct linked_list *next;
};

struct linked_list *create_list(struct bp data);
void insert_at(struct linked_list **list, struct bp data, int index);
void remove_at(struct linked_list **list, int index);
int len(struct linked_list *list);
struct bp search(struct linked_list *list, unsigned long long data);
void delete_list(struct linked_list **list);
void printList(struct linked_list **list);
struct bp get_at(struct linked_list **list, int index);
void append_list(struct linked_list **list, struct bp data);
struct bp set_breakpoint(pid_t pid, size_t address, char *name);
void remove_breakpoint(pid_t pid, struct bp bp);
void rm_n(char cmd[]);
void print_regs(struct user_regs_struct registers);
void print_maps(pid_t pid);
void read_memory(pid_t pid, char format, int count, size_t addr);
size_t get_symbol(pid_t pid, char *symbol);
unsigned long get_symbol_address(const char *path, const char *symbol_name);