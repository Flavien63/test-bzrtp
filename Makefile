CC = gcc
OPT = -c -Wextra -Wall -g -DONE=1
LDFLAGS = -Ibzrtp/include
LDLIBS = -Lbzrtp -lbzrtp

prog : main.o client.o
	$(CC) main.o client.o $(LDFLAGS) $(LDLIBS) -o prog

main.o : main.c main.h client.o
	$(CC) $(OPT) main.c

client.o : client.c client.h
	$(CC) $(OPT) client.c

clean :
	rm main.o client.o prog