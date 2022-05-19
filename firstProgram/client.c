#include "client.h"

clientContext_t * initClient(int * supportedAuthTag, int authTagLength, int * supportedCipher, int cipherLength, int * supportedHash, int hashLength, int * supportedKeyAgreement, int keyAgreementLength, int * supportedSas, int sasLength)
{
    clientContext_t * client = (clientContext_t *)malloc(sizeof(clientContext_t));

    if (!client)
    {
        printf("Mistake about the client context's init\n");
    }

    //mbedtls_ecdsa_init(&client->ctx_sign);
    //mbedtls_ecdsa_init(&client->ctx_verify);

    client->authTagLength = authTagLength;
    client->cipherLength = cipherLength;
    client->hashLength = hashLength;
    client->keyAgreementLength = keyAgreementLength;
    client->sasLength = sasLength;

    client->supportedAuthTag = (uint8_t *)malloc(client->authTagLength*sizeof(uint8_t));
    client->supportedCipher = (uint8_t *)malloc(client->cipherLength*sizeof(uint8_t));
    client->supportedHash = (uint8_t *)malloc(client->hashLength*sizeof(uint8_t));
    client->supportedKeyAgreement = (uint8_t *)malloc(client->keyAgreementLength*sizeof(uint8_t));
    client->supportedSas = (uint8_t *)malloc(client->sasLength*sizeof(uint8_t));

    if (!client->supportedAuthTag || !client->supportedCipher || !client->supportedHash || !client->supportedKeyAgreement || !client->supportedSas)
    {
        printf("Mistake about the supported algorithms malloc\n");
    }

    for (int i = 0; i < authTagLength; i++)
    {
        client->supportedAuthTag[i] = supportedAuthTag[i];
    }

    for (int i = 0; i < cipherLength; i++)
    {
        client->supportedCipher[i] = supportedCipher[i];
    }

    for (int i = 0; i < hashLength; i++)
    {
        client->supportedHash[i] = supportedHash[i];
    }

    for (int i = 0; i < keyAgreementLength; i++)
    {
        client->supportedKeyAgreement[i] = supportedKeyAgreement[i];
    }

    for (int i = 0; i < sasLength; i++)
    {
        client->supportedSas[i] = supportedSas[i];
    }

    client->previousReceiveQueueIndex = 0;
    client->receiveQueueIndex = 0;
    client->previousSendQueueIndex = 0;
    client->sendQueueIndex = 0;

    for (int i = 0; i < MAX_QUEUE_LENGTH; i++)
    {
        client->sendQueue[i].packetLength = 0;
        client->receiveQueue[i].packetLength = 0;

        for (int j = 0; j < MAX_PACKET_LENGTH; j++)
        {
            client->sendQueue[i].packetString[j] = 0;
            client->receiveQueue[i].packetString[j] = 0;
        }
    }

    return client;
}

void destroyClient(clientContext_t *client)
{
    free(client->supportedAuthTag);
    free(client->supportedCipher);
    free(client->supportedHash);
    free(client->supportedKeyAgreement);
    free(client->supportedSas);
    free(client);
}