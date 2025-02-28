CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Werror -pedantic 

SRC = my_strace.c printer.c


OBJ = ${SRC:.c=.o}

all: $(OBJ)
	$(CC) -o my_strace $^

clean:
	rm -f $(OBJ) my_strace
