#ifndef CONTACT_H
#define CONTACT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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