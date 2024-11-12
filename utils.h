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

#ifndef UTILS_H
#define UTILS_H


#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>


struct bp 
{
    size_t address;
    size_t data;
};

void set_breakpoint(pid_t pid, size_t address, struct bp *arr_bp, int *nb_bp);
//void remove_breakpoint(pid_t pid, struct bp bp, struct bp *arr_bp, int *nb_bp);
void rm_n(char cmd[]);
void print_regs(struct user_regs_struct registers);
void print_maps(pid_t pid);

#endif /* ! UTILS_H */