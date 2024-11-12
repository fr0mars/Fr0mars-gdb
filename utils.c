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

void set_breakpoint(pid_t pid, size_t address, struct bp *arr_bp, int *nb_bp)
{
    struct bp res;
    res.address = address;
    res.data = ptrace(PTRACE_PEEKDATA, pid, address, 0);
    ptrace(PTRACE_POKEDATA, pid, address, 0xCC);
    arr_bp[*nb_bp] = res;
    *nb_bp += 1;
}

// void remove_breakpoint(pid_t pid, struct bp bp, struct bp *arr_bp, int
// *nb_bp)
//{
//     ptrace(PTRACE_POKEDATA, pid, bp.address, bp.data);
// }

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
    char line[2048];
    while (fgets(line, sizeof(line), fp))
    {
        printf("%s", line);
    }
    fclose(fp);
    printf("\n");
}
