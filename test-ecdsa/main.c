#include "main.h"

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    printf( "%s", title );
    for( i = 0; i < len; i++ )
        printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    printf( "\n" );
}

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->MBEDTLS_PRIVATE(grp), &key->MBEDTLS_PRIVATE(Q),
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

int main(int args, char *argv[])
{
    int ret = 1;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    ((void) argv);

    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(sig, 0, sizeof(sig));
    memset(message, 0x25, sizeof(message));

    printf(" . Seeding the random generator...");

    mbedtls_entropy_init(&entropy);
    
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
    if (ret)
    {
        printf(" failed\n ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return ret;
    }

    printf(" ok\n . Generating key pair...");

    ret = mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret)
    {
        printf(" failed\n ! mbedtls_ecdsa_genkey returned %d\n", ret);
        return ret;
    }

    printf(" ok (key size: %d bits)\n", (int) ctx_sign.MBEDTLS_PRIVATE(grp).pbits);
    dump_pubkey(" + Public key: ", &ctx_sign);
    printf(" . Computing message hash...");

    ret = mbedtls_sha256(message, sizeof(message), hash, 0);
    if (ret)
    {
        printf(" failed\n mbedtls_sha256 returned %d\n", ret);
        return ret;
    }

    printf(" ok\n");
    dump_buf(" + Hash: ", hash, sizeof(hash));
    printf(" . Signing message hash...");

    ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret)
    {
        printf(" failed\n ! mbedtls_ecdsa_write_signature returned %d\n", ret);
        return ret;
    }

    printf(" ok (signature length = %u)\n", (unsigned int) sig_len);
    dump_buf(" + Signature: ", sig, sig_len);
    printf(" . Preparing verification context...");

    ret = mbedtls_ecp_group_copy(&ctx_verify.MBEDTLS_PRIVATE(grp), &ctx_sign.MBEDTLS_PRIVATE(grp));
    if (ret)
    {
        printf(" failed\n ! mbedtls_ecp_group_copy returned %d\n", ret);
        return ret;
    }

    ret = mbedtls_ecp_copy(&ctx_verify.MBEDTLS_PRIVATE(Q), &ctx_sign.MBEDTLS_PRIVATE(Q));
    if (ret)
    {
        printf(" failed\n ! mbedtls_ecp_copy returned %d\n", ret);
        return ret;
    }

    printf(" ok\n . Verifying signature...");

    ret = mbedtls_ecdsa_read_signature(&ctx_verify, hash, sizeof(hash), sig, sig_len);
    if (ret)
    {
        printf(" failed\n ! mbedtls_ecdsa_read_signature returned %d\n", ret);
        return ret;
    }

    printf(" ok\n");

    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}