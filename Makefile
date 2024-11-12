CC=gcc
CFLAGS=-Wall -Wextra -Wvla -g -std=c99 -pedantic

all: dbg

dbg: dbg.c
	$(CC) $(CFLAGS) -o my-dbg dbg.c utils.c

clean:
	rm -f my-dbg *.o
