#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bzrtp/include/bzrtp/bzrtp.h"
#include "bzrtp/include/cryptoUtils.h"
#include "bzrtp/include/packetParser.h"
#include "bzrtp/include/stateMachine.h"
#include "bzrtp/include/typedef.h"
#include "bzrtp/include/zidCache.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha512.h"
#include <string.h>

#define MAX_PACKET_LENGTH 1000

#define MAX_QUEUE_LENGTH 10

#define ERROR_INIT_CLIENTCONTEXT 0x01
#define ERROR_INIT_SUPPORTED 0x02

typedef struct packetDatas_struct {
	uint8_t packetString[MAX_PACKET_LENGTH];
	uint16_t packetLength;
} packetDatas_t;

typedef struct clientContext_struct
{
    bzrtpContext_t * context;
    uint8_t *supportedHash;
    uint8_t hashLength;
    uint8_t *supportedCipher;
    uint8_t cipherLength;
    uint8_t *supportedAuthTag;
    uint8_t authTagLength;
    uint8_t *supportedKeyAgreement;
    uint8_t keyAgreementLength;
    uint8_t *supportedSas;
    uint8_t sasLength;
    packetDatas_t sendQueue[MAX_QUEUE_LENGTH];
    uint8_t previousSendQueueIndex;
    uint8_t sendQueueIndex;
    packetDatas_t receiveQueue[MAX_QUEUE_LENGTH];
    uint8_t previousReceiveQueueIndex;
    uint8_t receiveQueueIndex;
    mbedtls_ecdsa_context ctx_sign;
    mbedtls_ecdsa_context ctx_verify;
} clientContext_t;

clientContext_t * initClient(int * supportedAuthTag, int authTagLength, int * supportedCipher, int cipherLength, int * supportedHash, int hashLength, int * supportedKeyAgreement, int keyAgreementLength, int * supportedSas, int sasLength);
void destroyClient(clientContext_t *client);

#endif