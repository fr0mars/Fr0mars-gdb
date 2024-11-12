#ifndef DBG_H
#define DBG_H

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

#endif /* ! DBG_H */