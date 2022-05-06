#include "contact.h"

contact_t * initContact(void)
{
    contact_t * contact = (contact_t *)malloc(sizeof(contact_t));

    for (int i = 0; i < 7; i++)
    {
        contact->supportedAuthTag[i] = 0;
        contact->supportedCipher[i] = 0;
        contact->supportedHash[i] = 0;
        contact->supportedKeyAgreement[i] = 0;
        contact->supportedSas[i] = 0;
    }

    return contact;
}

void destroyContact(contact_t *contact)
{
    free(contact);
}