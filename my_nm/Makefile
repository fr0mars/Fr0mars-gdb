CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Werror -pedantic 

SRC = my_nm.c


OBJ = ${SRC:.c=.o}

all: $(OBJ)
	$(CC) -o my_nm $^

clean:
	rm -f $(OBJ) my_nm