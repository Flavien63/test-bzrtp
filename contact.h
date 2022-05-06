#ifndef CONTACT_H
#define CONTACT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bzrtp/include/bzrtp/bzrtp.h"
#include "bzrtp/include/cryptoUtils.h"
#include "bzrtp/include/packetParser.h"
#include "bzrtp/include/stateMachine.h"
#include "bzrtp/include/typedef.h"
#include "bzrtp/include/zidCache.h"

typedef struct contact_struct
{
    uint8_t supportedHash[7];
    uint8_t supportedCipher[7];
    uint8_t supportedAuthTag[7];
    uint8_t supportedKeyAgreement[7];
    uint8_t supportedSas[7];
} contact_t;

contact_t * initContact(void);
void destroyContact(contact_t *contact);

#endif