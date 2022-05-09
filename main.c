#include "main.h"

int sendData(void * clientData, const uint8_t * packetString, uint16_t packetLength)
{
    clientContext_t *clientContext = (clientContext_t *) clientData;

    clientContext->sendQueue[clientContext->sendQueueIndex].packetLength = packetLength;

    for (int i = 0; i < packetLength; i++)
    {
        clientContext->sendQueue[clientContext->sendQueueIndex].packetString[i] = packetString[i];
    }

    clientContext->sendQueueIndex++;

    return 0;
}

int initCallbaks(bzrtpContext_t * context)
{
    bzrtpCallbacks_t * cbs = (bzrtpCallbacks_t *)malloc(sizeof(bzrtpCallbacks_t));

    cbs->bzrtp_sendData = sendData;
    cbs->bzrtp_contextReadyForExportedKeys = NULL;
    cbs->bzrtp_srtpSecretsAvailable = NULL;
    cbs->bzrtp_startSrtpSession = NULL;
    cbs->bzrtp_statusMessage = NULL;
    
    return bzrtp_setCallbacks(context, cbs);
}

int main(int args, char *argv[])
{
    bzrtpContext_t * contextAlice = bzrtp_createBzrtpContext();
    bzrtpContext_t * contextBob = bzrtp_createBzrtpContext();

    int retval;

    int AliceSSRC = 0;
    int BobSSRC = 0;

    int authTagLengthAlice = 4;
    int cipherLengthAlice = 6;
    int hashLengthAlice = 4;
    int keyAgreementLengthAlice = 7;
    int sasLengthAlice = 2;

    int authTagAlice[7] = {49, 40, 51, 52, 0, 0, 0};
    int cipherAlice[7] = {33, 34, 35, 36, 37, 38, 0};
    int hashAlice[7] = {17, 18, 19, 20, 0, 0, 0};
    int keyAgreementAlice[7] = {65, 66, 67, 68, 69, 70, 71};
    int sasAlice[7] = {81, 82, 0, 0, 0, 0, 0};

    int authTagLengthBob = 4;
    int cipherLengthBob = 6;
    int hashLengthBob = 4;
    int keyAgreementLengthBob = 7;
    int sasLengthBob = 2;

    int authTagBob[7] = {49, 40, 51, 52, 0, 0, 0};
    int cipherBob[7] = {33, 34, 35, 36, 37, 38, 0};
    int hashBob[7] = {17, 18, 19, 20, 0, 0, 0};
    int keyAgreementBob[7] = {65, 66, 67, 68, 69, 70, 71};
    int sasBob[7] = {81, 82, 0, 0, 0, 0, 0};

    if (!contextAlice || !contextBob)
    {
        printf("Erreur de création des contextes\n");
        return ERROR_CREATE_CONTEXT;
    }

    if (bzrtp_initBzrtpContext(contextAlice, AliceSSRC) || bzrtp_initBzrtpContext(contextBob, BobSSRC))
    {
        printf("Erreur d'initialisation des contextes\n");
        return ERROR_INIT_CONTEXT;
    }

    retval = initCallbaks(contextAlice) || initCallbaks(contextBob);

    if (retval)
    {
        printf("Erreur d'initialisation des Callbacks : %d\n", retval);
        return ERROR_INIT_CALLBACKS;
    }

    clientContext_t * Alice = initClient(authTagAlice, authTagLengthAlice, cipherAlice, cipherLengthAlice, hashAlice, hashLengthAlice, keyAgreementAlice, keyAgreementLengthAlice, sasAlice, sasLengthAlice);
    clientContext_t * Bob = initClient(authTagBob, authTagLengthBob, cipherBob, cipherLengthBob, hashBob, hashLengthBob, keyAgreementBob, keyAgreementLengthBob, sasBob, sasLengthBob);

    if (!Alice || !Bob)
    {
        printf("Erreur d'initialisation des clients\n");
        return ERROR_INIT_CLIENT;
    }

    retval = bzrtp_setClientData(contextAlice, AliceSSRC, Alice) || bzrtp_setClientData(contextBob, BobSSRC, Bob);

    if (retval)
    {
        printf("Erreur d'initialisation de clientData : %d\n", retval);
        return ERROR_INIT_CLIENTDATA;
    }

    if (bzrtp_startChannelEngine(contextAlice, AliceSSRC) || bzrtp_startChannelEngine(contextBob, BobSSRC))
    {
        printf("Erreur de démarrage des channels\n");
        return ERROR_START_CHANNEL;
    }

    retval = bzrtp_processMessage(contextBob, BobSSRC, contextAlice->channelContext[AliceSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID]->packetString, (ZRTP_PACKET_HEADER_LENGTH + contextAlice->channelContext[AliceSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t));

    if (retval)
    {
        printf("Erreur d'envoi du Hello : %d\n", retval);
        return ERROR_PROCESS_MESSAGE;
    }

    printf("Indice de queue d'envoi de Bob : %d\n", Bob->sendQueueIndex);
    printf("Indice de queue d'envoi précédent de Bob : %d\n", Bob->previousSendQueueIndex);
    printf("Indice de queue de réception de Bob : %d\n", Bob->receiveQueueIndex);
    printf("Indice de queue de réception précédent de Bob : %d\n", Bob->previousReceiveQueueIndex);

    printf("Indice de queue d'envoi d'Alice' : %d\n", Alice->sendQueueIndex);
    printf("Indice de queue d'envoi précédent d'Alice' : %d\n", Alice->previousSendQueueIndex);
    printf("Indice de queue de réception d'Alice' : %d\n", Alice->receiveQueueIndex);
    printf("Indice de queue de réception précédent d'Alice' : %d\n", Alice->previousReceiveQueueIndex);

    destroyClient(Alice);
    destroyClient(Bob);

    bzrtp_destroyBzrtpContext(contextAlice, AliceSSRC);
    bzrtp_destroyBzrtpContext(contextBob, BobSSRC);

    return 0;
}