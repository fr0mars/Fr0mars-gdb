/*
        ##################################
        #                                #
        #      My Debugging Suite        #
        #                                #
        #          Bit(e)wise:           #
        #                                #
        #       Matteo Ahouanto          #
        #       Julian Francisco         #
        #                                #
        #                                #
        ##################################


*/

#include "dbg.h"

static struct bp set_breakpoint(pid_t pid, size_t address)
{
    struct bp res;
    res.address = address;
    res.data = ptrace(PTRACE_PEEKDATA, pid, address, 0);

    size_t data = 0xCC;
    ptrace(PTRACE_POKEDATA, pid, address, data);
    return res;
}

static void remove_breakpoint(pid_t pid, struct bp bp)
{
    ptrace(PTRACE_POKEDATA, pid, bp.address, bp.data);
}

static void rm_n(char cmd[])
{
    for (int i = 0; cmd[i] != 0; i++)
    {
        if (cmd[i] == '\n')
            cmd[i] = 0;
    }
}

static void print_regs(struct user_regs_struct registers)
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

static void print_maps(pid_t pid)
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
    {
        printf("%s", line);
    }
    fclose(fp);
    printf("\n");
}

static void debug(pid_t pid)
{
    char cmd[128]; // arbitrary size atm
    while (1)
    {
        printf("dbg> ");
        fgets(cmd, sizeof(cmd), stdin);

        char *ptr = strtok(cmd, " ");
        rm_n(ptr);
        if (strcmp(ptr, "help") == 0)
        {
            printf("info_regs: display registers\n\
continue: continue program\n\
quit: exit\n\
help: display this\n");
        }

        else if (strcmp(ptr, "quit") == 0)
        {
            return;
        }
        else if (strcmp(ptr, "info_regs") == 0)
        {
            struct user_regs_struct registers;
            ptrace(PTRACE_GETREGS, pid, 0, &registers);
            print_regs(registers);
        }
        else if (strcmp(ptr, "info_memory") == 0)
        {
            print_maps(pid);
        }

        else if (strcmp(ptr, "break") == 0)
        {
            char *addr = strtok(NULL, " ");
            size_t address = strtol(addr, NULL, 16);
            struct bp bp = set_breakpoint(
                pid,
                address); // have to do a linked list of breakpoints to log them
            // printf("breakpoint set at 0x%lx\n", address);
        }

        else if (strcmp(ptr, "continue") == 0)
        {
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }

        else if (strcmp(ptr, "step") == 0)
        {
            ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
            waitpid(pid, NULL, 0);
        }
        else if (strcmp(ptr, "examine") == 0)
        {
            return;
            // TODO
        }
        else
        {
            printf("Unknown\n");
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("No binary given in input\n");
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], argv + 1);
    }
    else if (pid < 0)
    {
        perror("fork fail");
        return 1;
    }
    else
    {
        waitpid(pid, NULL, 0);
        debug(pid);
        return 0;
    }
}