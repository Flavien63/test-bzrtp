CC = gcc
OPT = -c -Wextra -Wall -g -DONE=1
CFLAGS = -I./mbedtls/include
LDFLAGS = -L./mbedtls/library
LDLIBS = -lmbedtls -lmbedx509 -lmbedcrypto

prog : main.o
	$(CC) main.o $(CFLAGS) $(LDFLAGS) $(LDLIBS) -o prog

main.o : main.c main.h
	$(CC) $(OPT) main.c

clean :
	rm main.o prog