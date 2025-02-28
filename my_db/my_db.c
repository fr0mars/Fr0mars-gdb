#include "utils.h"

static void debug(pid_t pid, char *path)
{
    char cmd[128];
    struct linked_list *bp_list = NULL;
    while (1)
    {
        printf("my-db> ");
        fgets(cmd, sizeof(cmd), stdin);

        char *ptr = strtok(cmd, " ");
        rm_n(ptr);
        if (strcmp(ptr, "help") == 0)
        {
            printf("DBS Menu:\n"
                   "1. continue                - Continue execution\n"
                   "2. break <address|function> - Set a breakpoint on an "
                   "address or function\n"
                   "3. next <n>                - Execute the next 'n' "
                   "instructions\n"
                   "4. quit                    - Exit the debugger\n"
                   "5. kill                    - Kill the child process\n"
                   "6. x|u|d <count> <address|register> - Read memory:\n"
                   "   x - Read memory in hexadecimal\n"
                   "   u - Read memory in unsigned decimal\n"
                   "   d - Read memory in signed decimal\n");
        }

        else if (strcmp(ptr, "quit") == 0 || strcmp(ptr, "q") == 0)
        {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            kill(pid, SIGKILL);
            exit(0);
        }

        else if (strcmp(ptr, "kill") == 0)
            ptrace(PTRACE_KILL, pid, NULL, NULL);

        else if (strcmp(ptr, "registers") == 0)
        {
            struct user_regs_struct registers;
            ptrace(PTRACE_GETREGS, pid, 0, &registers);
            print_regs(registers);
        }

        else if (strcmp(ptr, "info_memory") == 0)
            print_maps(pid);

        else if (strcmp(ptr, "x") == 0 || strcmp(ptr, "d") == 0
                 || strcmp(ptr, "u") == 0)
        {
            char *count = strtok(NULL, " ");
            char *addr = strtok(NULL, " ");
            rm_n(addr);
            if (!count || !addr)
                continue;

            unsigned long nb = strtoul(count, NULL, 0);
            if (nb == ULONG_MAX)
                continue;

            size_t address = get_symbol(pid, addr);
            if (address == 0)
                address = strtoul(addr, NULL, 0);
            if (address == 0)
                continue;
            read_memory(pid, ptr[0], nb, address);
        }

        else if (strcmp(ptr, "break") == 0)
        {
            char *addr = strtok(NULL, " ");
            if (!addr)
                continue;

            rm_n(addr);
            size_t address;
            char *name = NULL;
            unsigned long symbol_address = get_symbol_address(path, addr);
            if (symbol_address != 0)
            {
                address = symbol_address + 8;
                name = addr;
            }
            else
                address = strtoul(addr, NULL, 0);
            if (address == ULONG_MAX || address == 0)
                continue;
            struct bp srch = search(bp_list, address);
            if (srch.address != 0)
                continue;

            struct bp bp = set_breakpoint(pid, address, name);
            if (!bp_list)
                bp_list = create_list(bp);
            else
                append_list(&bp_list, bp);
            printf("\nbreakpoint placed at %#lx\n\n", address);
        }

        else if (strcmp(ptr, "blist") == 0)
            printList(&bp_list);

        else if (strcmp(ptr, "bdel") == 0)
        {
            long num = strtol(strtok(NULL, " "), NULL, 0);
            if (num == 0)
                continue;
            struct bp ith = get_at(&bp_list, num);
            remove_breakpoint(pid, ith);
            remove_at(&bp_list, num - 1);
        }
        else if (strcmp(ptr, "continue") == 0)
        {
            int status;
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            size_t rip = regs.rip - 1;
            long cur = ptrace(PTRACE_PEEKDATA, pid, rip, NULL);
            if (cur == 0xCC)
            {
                struct bp temp = search(bp_list, rip);
                remove_breakpoint(pid, temp);
                regs.rip = rip;
                ptrace(PTRACE_SETREGS, pid, 0, &regs);
                ptrace(PTRACE_CONT, pid, NULL, NULL);
                set_breakpoint(pid, temp.address, temp.name);
                waitpid(pid, &status, 0);
                if (WIFEXITED(status))
                {
                    printf("process exited\n");
                    exit(0);
                }
            }
            else
            {
                ptrace(PTRACE_CONT, pid, NULL, NULL);
                waitpid(pid, &status, 0);
                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
                {
                    ptrace(PTRACE_GETREGS, pid, 0, &regs);
                    printf("\nbreakpoint hit at %#llx\n\n", regs.rip - 1);
                }
                else if (WIFEXITED(status))
                {
                    printf("process exited\n");
                    exit(0);
                }
            }
        }

        else if (strcmp(ptr, "next") == 0)
        {
            unsigned long steps;
            char *steps_str = strtok(NULL, " ");
            if (!steps_str)
                steps = 1;
            else
                steps = strtoul(steps_str, NULL, 10);
            if (steps <= 0)
                continue;

            for (unsigned long i = 0; i < steps; i++)
            {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, 0, &regs);
                size_t rip = regs.rip - 1;
                long cur = ptrace(PTRACE_PEEKDATA, pid, rip, NULL);

                if (cur == 0xE8)
                {
                    size_t ret = rip + 5 + (int)(cur >> 8);
                    struct bp bp = set_breakpoint(pid, ret, NULL);
                    ptrace(PTRACE_CONT, pid, NULL, NULL);
                    waitpid(pid, NULL, 0);
                    remove_breakpoint(pid, bp);
                }
                if (cur == 0xCC)
                {
                    struct bp temp = search(bp_list, rip);
                    remove_breakpoint(pid, temp);
                    regs.rip = rip;
                    ptrace(PTRACE_SETREGS, pid, 0, &regs);
                    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                    set_breakpoint(pid, temp.address, temp.name);
                    waitpid(pid, NULL, 0);
                }
                else
                {
                    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                    waitpid(pid, NULL, 0);
                }
            }
        }
        else
            printf("Unknown\n");
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
        return 1;
    else
    {
        waitpid(pid, NULL, 0);
        debug(pid, argv[1]);
        return 0;
    }
}
