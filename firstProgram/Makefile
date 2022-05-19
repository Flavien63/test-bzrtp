CC = gcc
OPT = -c -Wextra -Wall -g -DONE=1 -std=c99
CFLAGS = -I./bzrtp/include -I./mbedtls/include
LDFLAGS = -L./bzrtp -L./mbedtls/library
LDLIBS = -lbzrtp -lmbedtls -lmbedx509 -lmbedcrypto

prog : main.o client.o
	$(CC) main.o client.o $(CFLAGS) $(LDFLAGS) $(LDLIBS) -o prog

main.o : main.c main.h client.o
	$(CC) $(OPT) main.c

client.o : client.c client.h
	$(CC) $(OPT) client.c

clean :
	rm main.o client.o prog