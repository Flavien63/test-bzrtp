CC = clang
OPT = -c -Wextra -Wall -std=c99
CFLAGS = -I../bzrtp/include -I../bzrtp/include/dilithium -I../bzrtp/include/kyber
LDFLAGS = -L../bzrtp	-L../bzrtp/include/dilithium -L../bzrtp/include/kyber
LDLIBS = -lbzrtp -lbctoolbox -ldilithium5_clean -lkyber1024_clean

COMMON_DIR=../bzrtp/include/common
COMMON_FILES=$(COMMON_DIR)/aes.c $(COMMON_DIR)/sha2.c $(COMMON_DIR)/fips202.c $(COMMON_DIR)/nistseedexpander.c $(COMMON_DIR)/randombytes.c $(COMMON_DIR)/sp800-185.c

prog : main.o $(COMMON_FILES)
	$(CC) main.o $(CFLAGS) $(COMMON_FILES) -o prog $(LDFLAGS) $(LDLIBS)

main.o : main.c main.h
	$(CC) $(OPT) main.c

clean :
	rm main.o prog