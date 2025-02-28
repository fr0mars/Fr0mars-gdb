#include "utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <time.h>

struct linked_list *create_list(struct bp data)
{
    struct linked_list *newNode =
        (struct linked_list *)malloc(sizeof(struct linked_list));
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

void append_list(struct linked_list **list, struct bp data)
{
    struct linked_list *new = create_list(data);
    if (!*list)
    {
        *list = new;
        return;
    }
    struct linked_list *temp = *list;
    while (temp->next)
        temp = temp->next;
    temp->next = new;
}

void insert_at(struct linked_list **list, struct bp data, int index)
{
    struct linked_list *new = create_list(data);

    if (!index)
    {
        new->next = *list;
        *list = new;
        return;
    }

    struct linked_list *temp = *list;
    for (int i = 0; i < index - 1 && temp; i++)
        temp = temp->next;

    if (!temp)
    {
        free(new);
        return;
    }

    new->next = temp->next;
    temp->next = new;
}

void remove_at(struct linked_list **list, int index)
{
    if (!*list)
        return;

    if (!index)
    {
        struct linked_list *temp = *list;
        *list = temp->next;
        free(temp);
        return;
    }

    struct linked_list *temp = *list;
    for (int i = 0; i < index - 1 && temp->next; i++)
        temp = temp->next;

    if (!temp->next)
        return;

    struct linked_list *to_rm = temp->next;
    temp->next = to_rm->next;
    free(to_rm);
}

int len(struct linked_list *list)
{
    int count = 0;
    while (list != NULL)
    {
        count++;
        list = list->next;
    }
    return count;
}

struct bp search(struct linked_list *list, unsigned long long data)
{
    while (list)
    {
        if (list->data.address == data)
            return list->data;

        list = list->next;
    }
    return (struct bp){ 0 };
}

struct bp get_at(struct linked_list **list, int index)
{
    struct linked_list *temp = *list;
    for (int i = 0; i < index - 1 && temp; i++)
        temp = temp->next;
    return temp->data;
}

void delete_list(struct linked_list **list)
{
    struct linked_list *temp = *list;
    while (temp)
    {
        struct linked_list *to_rm = temp;
        temp = temp->next;
        free(to_rm);
    }
    *list = NULL;
}

void printList(struct linked_list **list)
{
    int i = 1;
    struct linked_list *temp = *list;
    while (temp)
    {
        printf("%d %lx %s\n", i, temp->data.address, temp->data.name);
        temp = temp->next;
        i++;
    }
}

struct bp set_breakpoint(pid_t pid, size_t address, char *name)
{
    struct bp res;
    res.address = address;
    res.data = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
    res.name = strdup(name);
    size_t data = 0xCC;
    ptrace(PTRACE_POKEDATA, pid, address, data);
    return res;
}

void remove_breakpoint(pid_t pid, struct bp bp)
{
    ptrace(PTRACE_POKEDATA, pid, bp.address, bp.data);
}

void rm_n(char cmd[])
{
    for (int i = 0; cmd[i] != 0; i++)
    {
        if (cmd[i] == '\n')
            cmd[i] = 0;
    }
}

void print_regs(struct user_regs_struct registers)
{
    printf("rip: 0x%llx\n", registers.rip);
    printf("rsp: 0x%llx\n", registers.rsp);
    printf("rbp: 0x%llx\n", registers.rbp);
    printf("eflags: 0x%llx\n", registers.eflags);
    printf("orig_rax: 0x%llx\n", registers.orig_rax);
    printf("rax: 0x%llx\n", registers.rax);
    printf("rbx: 0x%llx\n", registers.rbx);
    printf("rcx: %llx\n", registers.rcx);
    printf("rdx: 0x%llx\n", registers.rdx);
    printf("rdi: 0x%llx\n", registers.rdi);
    printf("rsi: 0x%llx\n", registers.rsi);
    printf("r8: 0x%llx\n", registers.r8);
    printf("r9: 0x%llx\n", registers.r9);
    printf("r10: 0x%llx\n", registers.r10);
    printf("r11: 0x%llx\n", registers.r11);
    printf("r12: 0x%llx\n", registers.r12);
    printf("r13: 0x%llx\n", registers.r13);
    printf("r14: 0x%llx\n", registers.r14);
    printf("r15: 0x%llx\n", registers.r15);
    printf("cs: 0x%llx\n", registers.cs);
    printf("ds: 0x%llx\n", registers.ds);
    printf("es: 0x%llx\n", registers.es);
    printf("fs: 0x%llx\n", registers.fs);
    printf("gs: 0x%llx\n", registers.gs);
    printf("ss: 0x%llx\n", registers.ss);
    printf("fs_base: 0x%llx\n", registers.fs_base);
    printf("gs_base: 0x%llx\n\n", registers.gs_base);
}

void print_maps(pid_t pid)
{
    char maps[256];
    sprintf(maps, "/proc/%d/maps", pid);
    FILE *fp = fopen(maps, "r");
    if (fp == NULL)
    {
        printf("Error\n");
        exit(1);
    }
    char line[2048];
    while (fgets(line, sizeof(line), fp) != NULL)
        printf("%s", line);
    fclose(fp);
    printf("\n");
}

size_t get_symbol(pid_t pid, char *symbol)
/* insupportable cette fonction
soit je suis abruti soit jsp mais ca marche comme ca*/
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (strcmp("$r15", symbol) == 0)
        return regs.r15;
    else if (strcmp("$r14", symbol) == 0)
        return regs.r14;
    else if (strcmp("$r13", symbol) == 0)
        return regs.r13;
    else if (strcmp("$r13", symbol) == 0)
        return regs.r12;
    else if (strcmp("$rbp", symbol) == 0)
        return regs.rbp;
    else if (strcmp("$rbx", symbol) == 0)
        return regs.rbx;
    else if (strcmp("$r11", symbol) == 0)
        return regs.r11;
    else if (strcmp("$r10", symbol) == 0)
        return regs.r10;
    else if (strcmp("$r9", symbol) == 0)
        return regs.r9;
    else if (strcmp("$r8", symbol) == 0)
        return regs.r8;
    else if (strcmp("$rax", symbol) == 0)
        return regs.rax;
    else if (strcmp("$rcx", symbol) == 0)
        return regs.rcx;
    else if (strcmp("$rdx", symbol) == 0)
        return regs.rdx;
    else if (strcmp("$rdi", symbol) == 0)
        return regs.rdi;
    else if (strcmp("$orig_rax", symbol) == 0)
        return regs.orig_rax;
    else if (strcmp("$rip", symbol) == 0)
        return regs.rip;
    else if (strcmp("$cs", symbol) == 0)
        return regs.cs;
    else if (strcmp("$eflags", symbol) == 0)
        return regs.eflags;
    else if (strcmp("$rsp", symbol) == 0)
        return regs.rsp;
    else if (strcmp("$ss", symbol) == 0)
        return regs.ss;
    else if (strcmp("$fs_base", symbol) == 0)
        return regs.fs_base;
    else if (strcmp("$gs_base", symbol) == 0)
        return regs.gs_base;
    else if (strcmp("$ds", symbol) == 0)
        return regs.ds;
    else if (strcmp("$es", symbol) == 0)
        return regs.es;
    else if (strcmp("$fs", symbol) == 0)
        return regs.fs;
    else if (strcmp("$gs", symbol) == 0)
        return regs.gs;
    else
        return 0;
}

void read_memory(pid_t pid, char fmt, int count, size_t addr)
{
    for (int i = 0; i < count; i++)
    {
        long cur = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

        switch (fmt)
        {
        case 'x':
            printf("0x%lx\n", cur);
            break;
        case 'd':
            printf("%ld\n", cur);
            break;
        case 'u':
            printf("%lu\n", cur);
            break;
        default:
            return;
        }
        addr += 8;
    }
}

unsigned long get_symbol_address(const char *path, const char *symbol_name)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)
        return 0;

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        close(fd);
        return 0;
    }

    char *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        close(fd);
        return 0;

        close(fd);
    }
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;

    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
    {
        munmap(map, st.st_size);
        return 0;
    }

    unsigned long offset = ehdr->e_shoff;
    Elf64_Shdr *sections = (Elf64_Shdr *)(map + offset);
    char *section_names = map + (&sections[ehdr->e_shstrndx])->sh_offset;

    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;
    for (unsigned short i = 0; i < ehdr->e_shnum; i++)
    {
        if (sections[i].sh_type == SHT_SYMTAB)
            symtab_hdr = &sections[i];
        else if (sections[i].sh_type == SHT_STRTAB
                 && strcmp(section_names + sections[i].sh_name, ".strtab") == 0)
            strtab_hdr = &sections[i];
    }
    if (symtab_hdr == NULL || strtab_hdr == NULL)
    {
        munmap(map, st.st_size);
        return 0;
    }

    Elf64_Sym *symtab = (Elf64_Sym *)(map + symtab_hdr->sh_offset);
    const char *strtab = (char *)(map + strtab_hdr->sh_offset);
    unsigned long nb_symbols = symtab_hdr->sh_size / sizeof(Elf64_Sym);
    for (unsigned long i = 0; i < nb_symbols; i++)
    {
        if (strcmp(strtab + symtab[i].st_name, symbol_name) == 0)
        {
            Elf64_Sym *symbol = &symtab[i];
            Elf64_Shdr *section = &sections[symbol->st_shndx];

            if (symbol->st_shndx == SHN_UNDEF || section->sh_addr == 0)
            {
                munmap(map, st.st_size);
                return 0;
            }

            unsigned long real_address = symbol->st_value;
            munmap(map, st.st_size);
            return real_address;
        }
    }

    munmap(map, st.st_size);
    return 0;
}
