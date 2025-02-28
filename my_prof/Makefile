CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Werror -pedantic 

SRC = my_prof.c


OBJ = ${SRC:.c=.o}

all: $(OBJ)
	$(CC) -o my_prof $^

clean:
	rm -f $(OBJ) my_prof