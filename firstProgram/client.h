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
#include <string.h>

#define ERROR_INIT_CLIENTCONTEXT 0x01
#define ERROR_INIT_SUPPORTED 0x02

clientContext_t * initClient(int * supportedAuthTag, int authTagLength, int * supportedCipher, int cipherLength, int * supportedHash, int hashLength, int * supportedKeyAgreement, int keyAgreementLength, int * supportedSas, int sasLength);
void destroyClient(clientContext_t *client);

#endif