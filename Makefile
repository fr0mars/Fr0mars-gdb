CC=gcc
CFLAGS=-Wall -Wextra -Wvla -g -std=c99 -pedantic

all: dbg

dbg: dbg.c
	$(CC) $(CFLAGS) -o my-dbg dbg.c

clean:
	rm -f dbg *.o
