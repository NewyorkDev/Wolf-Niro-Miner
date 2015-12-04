CC		= gcc
LD		= gcc
CFLAGS 	= -D_POSIX_SOURCE -D_GNU_SOURCE -O0 -ggdb3 -std=c11 -pthread  -c
LDFLAGS	= -pthread -O0 -ggdb3 
LIBS	= -ljansson -lOpenCL -ldl

all:
	$(CC) $(CFLAGS) log.c -o log.o
	$(CC) $(CFLAGS) net.c -o net.o
	$(CC) $(CFLAGS) minerutils.c -o minerutils.o
	$(CC) $(CFLAGS) gpu.c -o gpu.o
	$(CC) $(CFLAGS) main.c -o main.o
	$(LD) $(LDFLAGS) log.o net.o minerutils.o gpu.o main.o $(LIBS) -o miner

clean:
	rm -f miner *.o