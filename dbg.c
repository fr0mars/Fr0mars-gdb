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

#include "utils.h"

static void debug(pid_t pid)
{
    char cmd[256];
    struct bp *arr_bp = malloc(sizeof(struct bp) * 128);
    int nb_bp = 0;

    // int *status;
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
help: display this\n\
info_memory: prints mem maps\n");
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
            set_breakpoint(pid, address, arr_bp, &nb_bp);
        }

        else if (strcmp(ptr, "continue") == 0)
        {
            ptrace(PTRACE_CONT, pid, 0, 0);
            waitpid(pid, NULL, 0);
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