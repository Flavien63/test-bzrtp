#include "main.h"

int main(int argc, char *argv[])
{
    int ok = 0;

    uint8_t * publicKey = (uint8_t *)malloc(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES * sizeof(uint8_t));
    uint8_t * privateKey = (uint8_t *)malloc(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES * sizeof(uint8_t));

    uint8_t * signature = (uint8_t *)malloc(PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES * sizeof(uint8_t));
    size_t sig_len;
    uint8_t * m = (uint8_t *)malloc(32 * sizeof(uint8_t));
    for (int i = 0; i < 32; i++)
    {
        m[i] = i;
    }
    size_t m_len = 32;

    ok = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(publicKey, privateKey);

    printf("Public Key : ");
    for (int i = 0; i < PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES; i++)
    {
        printf("%c%c", "0123456789ABCDEF" [publicKey[i] / 16], "0123456789ABCDEF" [publicKey[i] % 16]);
    }
    printf("\n");

    printf("Private Key : ");
    for (int i = 0; i < PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES; i++)
    {
        printf("%c%c", "0123456789ABCDEF" [privateKey[i] / 16], "0123456789ABCDEF" [privateKey[i] % 16]);
    }
    printf("\n");

    ok = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(signature, &sig_len, m, m_len, privateKey);

    printf("Signature : ");
    for (int i = 0; i < PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES; i++)
    {
        printf("%c%c", "0123456789ABCDEF" [signature[i] / 16], "0123456789ABCDEF" [signature[i] % 16]);
    }
    printf("\n");

    ok = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(signature, sig_len, m, m_len, publicKey);

    if (ok == 0)
    {
        printf("Signature ok\n");
    }

    free(publicKey);
    free(privateKey);
    free(signature);
    free(m);

    return 0;
}
