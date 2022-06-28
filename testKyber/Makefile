CC=clang
OPT=-c -Wextra -Wall -Wpedantic -Wmissing-prototypes -std=c99
CFLAGS=-I./kyber
LDFLAGS=-L./kyber
LDLIBS=-lkyber768_clean

COMMON_DIR=./common
COMMON_FILES=$(COMMON_DIR)/aes.c $(COMMON_DIR)/sha2.c $(COMMON_DIR)/fips202.c $(COMMON_DIR)/nistseedexpander.c $(COMMON_DIR)/randombytes.c $(COMMON_DIR)/sp800-185.c

prog : main.o $(COMMON_FILES)
	$(CC) main.o -DPQCLEAN_NAMESPACE=PQCLEAN_KYBER768_CLEAN $(CFLAGS) $(COMMON_FILES) -o prog $(LDFLAGS) $(LDLIBS)

main.o : main.c main.h
	$(CC) $(OPT) main.c

clean :
	rm main.o prog