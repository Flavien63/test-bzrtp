CC = gcc
OPT = -c -Wextra -Wall -g -DONE=1
LDFLAGS = -Ibzrtp/include
LDLIBS = -Lbzrtp -lbzrtp

prog : main.o contact.o
	$(CC) main.o contact.o $(LDFLAGS) $(LDLIBS) -o prog

main.o : main.c main.h contact.o
	$(CC) $(OPT) main.c

contact.o : contact.c contact.h
	$(CC) $(OPT) contact.c

clean :
	rm main.o contact.o prog