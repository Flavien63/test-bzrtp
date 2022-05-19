#ifndef MAIN_H
#define MAIN_H

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha512.h"
#include <string.h>

#define ECPARAMS MBEDTLS_ECP_DP_SECP192R1

static void dump_buf( const char *title, unsigned char *buf, size_t len );

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key );

int main(int args, char *argv[]);

#endif