CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Werror -pedantic 

SRC = my_db.c utils.c


OBJ = ${SRC:.c=.o}

all: $(OBJ)
	$(CC) -o my_db $^

clean:
	rm -f $(OBJ) my_db