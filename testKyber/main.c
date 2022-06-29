#include "main.h"

int main()
{
    int ok = 0;

    uint8_t * publicKey = (uint8_t *)malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES * sizeof(uint8_t));
    uint8_t * privateKey = (uint8_t *)malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES * sizeof(uint8_t));
    uint8_t * cipherText = (uint8_t *)malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES * sizeof(uint8_t));
    uint8_t * sharedSecret = (uint8_t *)malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES * sizeof(uint8_t));
    uint8_t * sharedSecretPeer = (uint8_t *)malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES * sizeof(uint8_t));

    printf("Public key length : %d\nPrivate key length : %d\n", PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES, PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES);

    ok = PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(publicKey, privateKey);

    printf("Public Key : ");
    for (int i = 0; i < PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES; i++)
    {
        printf("%c%c", "0123456789ABCDEF" [publicKey[i] / 16], "0123456789ABCDEF" [publicKey[i] % 16]);
    }
    printf("\n");

    printf("Private Key : ");
    for (int i = 0; i < PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES; i++)
    {
        printf("%c%c", "0123456789ABCDEF" [privateKey[i] / 16], "0123456789ABCDEF" [privateKey[i] % 16]);
    }
    printf("\n");

    ok = PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(cipherText, sharedSecret, publicKey);

    printf("Shared Secret : ");
    for (int i = 0; i < PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES; i++)
    {
        printf("%d ", sharedSecret[i]);
    }
    printf("\n");

    ok = PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(sharedSecretPeer, cipherText	, privateKey);

    printf("Shared Secret Peer : ");
    for (int i = 0; i < PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES; i++)
    {
        printf("%d ", sharedSecretPeer[i]);
    }
    printf("\n");

    int ret = 0;
    for (int i = 0; i < PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES; i++)
    {
        if (sharedSecret[i] != sharedSecretPeer[i])
            ret = 1;
    }

    if (ret)
        printf("Shared Secret are not the same\n");
    else
        printf("Shared Secret are the same\n");

    return 0;
}