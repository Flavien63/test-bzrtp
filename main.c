#include "main.h"

/*
 * @brief Put data in a queue to send to peer
 *
 * @param[in] clientData The client context with the queue
 * @param[in] packetString The packet string of what we want to send
 * @param[in] packetLength The length of the packet string
 * 
 * @return Return 0 if success
 */

int sendData(void * clientData, const uint8_t * packetString, uint16_t packetLength)
{
    /* Get the client context from clientData */
    clientContext_t *clientContext = (clientContext_t *) clientData;

    /* Get the length of the packet for copying the packetString */
    clientContext->sendQueue[clientContext->sendQueueIndex].packetLength = packetLength;

    /* Get the packetSring into the queue int by int */
    for (int i = 0; i < packetLength; i++)
    {
        clientContext->sendQueue[clientContext->sendQueueIndex].packetString[i] = packetString[i];
    }

    /* We increment the index to know that we have a new packet */
    clientContext->sendQueueIndex++;

    return 0;
}

/*
 * @brief Compare secrets of the two clients a and b
 *
 * @param[in] a The client a
 * @param[in] b The client b
 * @param[in] mainChannel Indicate if the uses channel are the main or not
 * 
 * @return Return 0 if success and some negative numbers else
 */

int compareSecrets(bzrtpSrtpSecrets_t *a, bzrtpSrtpSecrets_t* b, uint8_t mainChannel) 
{
    /* Test about the SAS */
	if (mainChannel==TRUE) {
		if (strcmp(a->sas,b->sas)!=0) {
			return -1;
		}
	}

    /* Tests about the diffrent algorithm we use */
	if (mainChannel == TRUE) {
		if ((a->authTagAlgo!=b->authTagAlgo)
		  || a->hashAlgo!=b->hashAlgo
		  || a->keyAgreementAlgo!=b->keyAgreementAlgo
		  || a->sasAlgo!=b->sasAlgo
		  || a->cipherAlgo!=b->cipherAlgo) {
			return -2;
		}
	} else {
		if ((a->authTagAlgo!=b->authTagAlgo)
		  || a->hashAlgo!=b->hashAlgo
		  || a->keyAgreementAlgo!=b->keyAgreementAlgo
		  || a->cipherAlgo!=b->cipherAlgo) {
			return -2;
		}
	}

    /* Tests about the different salt and their lengths */
	if (a->selfSrtpKeyLength==0 || b->selfSrtpKeyLength==0
	 || a->selfSrtpSaltLength==0 || b->selfSrtpSaltLength==0
	 || a->peerSrtpKeyLength==0 || b->peerSrtpKeyLength==0
	 || a->peerSrtpSaltLength==0 || b->peerSrtpSaltLength==0) {
		return -3;
	}

    /* Tests about the different salt and their contents */
	if (a->selfSrtpKeyLength != b->peerSrtpKeyLength
	 || a->selfSrtpSaltLength != b->peerSrtpSaltLength
	 || a->peerSrtpKeyLength != b->selfSrtpKeyLength
	 || a->peerSrtpSaltLength != b->selfSrtpSaltLength) {
		return -4;
	}

    /* Tests about the salt and their contents in memory */
	if (memcmp (a->selfSrtpKey, b->peerSrtpKey, b->peerSrtpKeyLength) != 0
	 || memcmp (a->selfSrtpSalt, b->peerSrtpSalt, b->peerSrtpSaltLength) != 0
	 || memcmp (a->peerSrtpKey, b->selfSrtpKey, b->selfSrtpKeyLength) != 0
	 || memcmp (a->peerSrtpSalt, b->selfSrtpSalt, b->selfSrtpSaltLength) != 0) {
		return -5;
	}

	return 0;
}

/*
 * @brief Main fonction thanks we use the BZRTP protocol
 * 
 * @return return 0 if success
 */
int main(int args, char *argv[])
{
    /* Creation of the context of which client, there is two clients, Alice and Bob */
    bzrtpContext_t * contextAlice = bzrtp_createBzrtpContext();
    bzrtpContext_t * contextBob = bzrtp_createBzrtpContext();

    /* The value that we use for debug and we return at the end */
    int retval;

    /* The channel in which we want to communciate, here we are doing this to the channel zero */
    int AliceSSRC = 0;
    int BobSSRC = 0;

    /* The algorithm that Alice can use with BZRTP */
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

    /* The algorithm that Bob can use with BZRTP */
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

    /* We are searching if the context creation was good or not */
    if (!contextAlice || !contextBob)
    {
        printf("Mistake about the bzrtp_createBzrtpContext\n");
        return ERROR_CREATE_CONTEXT;
    }

    /* We are searching if the context init was good or not and we are doing the init by the same time */
    if (bzrtp_initBzrtpContext(contextAlice, AliceSSRC) || bzrtp_initBzrtpContext(contextBob, BobSSRC))
    {
        printf("Mistake about the bzrtp_initBzrtpContext\n");
        return ERROR_INIT_CONTEXT;
    }

    /* Creation of the callbacks that we will use for the both clients */
    bzrtpCallbacks_t * cbs = (bzrtpCallbacks_t *)malloc(sizeof(bzrtpCallbacks_t));

    cbs->bzrtp_sendData = sendData;
    cbs->bzrtp_contextReadyForExportedKeys = NULL;
    cbs->bzrtp_srtpSecretsAvailable = NULL;
    cbs->bzrtp_startSrtpSession = NULL;
    cbs->bzrtp_statusMessage = NULL;
    
    retval = bzrtp_setCallbacks(contextAlice, cbs) || bzrtp_setCallbacks(contextBob, cbs);

    /* We are searching if the callbacks attribution was good or not */
    if (retval)
    {
        printf("Mistake about the callbacks init : %d\n", retval);
        return ERROR_INIT_CALLBACKS;
    }

    /* Init the client context of Alice and Bob */
    clientContext_t * Alice = initClient(authTagAlice, authTagLengthAlice, cipherAlice, cipherLengthAlice, hashAlice, hashLengthAlice, keyAgreementAlice, keyAgreementLengthAlice, sasAlice, sasLengthAlice);
    clientContext_t * Bob = initClient(authTagBob, authTagLengthBob, cipherBob, cipherLengthBob, hashBob, hashLengthBob, keyAgreementBob, keyAgreementLengthBob, sasBob, sasLengthBob);

    /* We are searching if the client context init was good or not */
    if (!Alice || !Bob)
    {
        printf("Mistake about the client context init\n");
        return ERROR_INIT_CLIENT;
    }

    /* Now we are setting the clientData by the client context */
    retval = bzrtp_setClientData(contextAlice, AliceSSRC, Alice) || bzrtp_setClientData(contextBob, BobSSRC, Bob);
    
    /* We are searching if the set was good or not */
    if (retval)
    {
        printf("Mistake about the clientData init : %d\n", retval);
        return ERROR_INIT_CLIENTDATA;
    }

    /* We start the channel were we want to exchange and by the same time we are searching if it was good or not */
    if (bzrtp_startChannelEngine(contextAlice, AliceSSRC) || bzrtp_startChannelEngine(contextBob, BobSSRC))
    {
        printf("Mistake about the channel start\n");
        return ERROR_START_CHANNEL;
    }

    /* Put the hello message of Alice in the receive Queue of Bob, we know now that he has to treat this packet to begin the ZRTP protocol */
    Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = (ZRTP_PACKET_HEADER_LENGTH + contextAlice->channelContext[AliceSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);

    for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
    {
        Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = contextAlice->channelContext[AliceSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID]->packetString[i];
    }

    Bob->receiveQueueIndex++;

    /* Bob is now processing the message that he receive from Alice */
    retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

    Bob->previousReceiveQueueIndex++;

    /* We are searching if the Hello Message war good or not */
    if (retval)
    {
        printf("Mistake about the sending of Alice's Hello message : %d\n", retval);
        return ERROR_PROCESS_MESSAGE;
    }

    /* Put the HelloAck message of Bob in the receive queue of Alice */
    Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = Bob->sendQueue[Bob->previousSendQueueIndex].packetLength;

    for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
    {
        Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = Bob->sendQueue[Bob->previousSendQueueIndex].packetString[i];
    }

    Bob->previousSendQueueIndex++;
    Alice->receiveQueueIndex++;

    /* Alice is now processing the Ack that she receive from Bob and now wait for the Hello message of Bob */
    retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

    Alice->previousReceiveQueueIndex++;

    /* We are searching if the HelloAck was correctly send and treat */
    if (retval)
    {
        printf("Mistake about the sending of Bob's HelloAck message : %d\n", retval);
        return ERROR_PROCESS_MESSAGE;
    }

    /* We are updating the Hello Packet of Bob because it was created too early and is know a bit late */
    retval = bzrtp_packetUpdateSequenceNumber(contextBob->channelContext[BobSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID], contextBob->channelContext[BobSSRC]->selfSequenceNumber);

    /* We are searching if the update was good or not */
    if (retval)
    {
        printf("Mistake about the update of Bob's Hello message : %d\n", retval);
        return ERROR_UPDATE_PACKET;
    }

    /* Put the Hello message of Bob in the queue of Alice */
    Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (contextBob->channelContext[BobSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_HEADER_LENGTH + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);
    
    for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
    {
        Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = contextBob->channelContext[BobSSRC]->selfPackets[HELLO_MESSAGE_STORE_ID]->packetString[i];
    }

    Alice->receiveQueueIndex++;

    /* Alice is now processing the Hello message */
    retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

    Alice->previousReceiveQueueIndex++;

    /* We are searching if the treatment of the Hello was good or not */
    if (retval)
    {
        printf("Mistake about the sending of Bob's Hello message : %d\n", retval);
        return ERROR_PROCESS_MESSAGE;
    }

    /* Put the HelloAck and the Alice's Commit in the Bob's queue */
    Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

    for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
    {
        Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
    }

    Alice->previousSendQueueIndex++;
    Alice->previousSendQueueIndex++;
    Bob->receiveQueueIndex++;

    /* Bob is now processing the HelloAck message */
    retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

    Bob->previousReceiveQueueIndex++;
    Bob->sendQueueIndex--;

    /* We are searching if the treatment of the HelloAck was good or not */
    if (retval)
    {
        printf("Mistake about the sending of Alice's HelloAck message : %d\n", retval);
        return ERROR_PROCESS_MESSAGE;
    }

    /* Update the Commit packet of Bob */
    retval = bzrtp_packetUpdateSequenceNumber(contextBob->channelContext[BobSSRC]->selfPackets[COMMIT_MESSAGE_STORE_ID], contextBob->channelContext[BobSSRC]->selfSequenceNumber);

    /* We are searching if the update was good or not */
    if (retval)
    {
        printf("Mistake about the update of Bob's Commit message : %d\n", retval);
        return ERROR_UPDATE_PACKET;
    }

    /* Put the Commit packet of Bob in the queue of Alice */
    Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (contextBob->channelContext[BobSSRC]->selfPackets[COMMIT_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_HEADER_LENGTH + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);

    for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
    {
        Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = contextBob->channelContext[BobSSRC]->selfPackets[COMMIT_MESSAGE_STORE_ID]->packetString[i];
    }

    Alice->receiveQueueIndex++;

    /* Alice is processing the Commit Message */
    retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

    Alice->previousReceiveQueueIndex++;

    /* We are searching if the sending was good or not */
    if (retval)
    {
        printf("Mistake about the sending of Bob's Commit : %d\n", retval);
        return ERROR_PROCESS_MESSAGE;
    }

    /* We are searching if Alice is the responder or not, it depends on the HVI */
    if (Alice->sendQueue[Alice->previousSendQueueIndex].packetLength)
    {
        printf("Alice is Responder and bob is Initiator\n");

        /* Put the Alice's DHPart1 packet in the Bob's queue */
        Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

        for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
        {
            Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
        }

        Alice->previousSendQueueIndex++;
        Bob->receiveQueueIndex++;

        /* Bob is now processing the DHPart1 message of Alice */
        retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

        Bob->previousReceiveQueueIndex++;

        /* We are searching if the sending of Alice's DHPart 1 was good or not */
        if (retval)
        {
            printf("Mistake about the sending of Alice's DHPart 1 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Update the Bob's DHPart 2 */
        retval = bzrtp_packetUpdateSequenceNumber(contextBob->channelContext[BobSSRC]->selfPackets[DHPART_MESSAGE_STORE_ID], contextBob->channelContext[BobSSRC]->selfSequenceNumber);

        if (retval)
        {
            printf("Erreur dans la mise à jour de DHPART2 de Bob : %d\n", retval);
            return ERROR_UPDATE_PACKET;
        }

        /* Put the DHPart 2 of Bob in the Alice's queue */
        Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (contextBob->channelContext[BobSSRC]->selfPackets[DHPART_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_HEADER_LENGTH + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);

        for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
        {
            Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = contextBob->channelContext[BobSSRC]->selfPackets[DHPART_MESSAGE_STORE_ID]->packetString[i];
        }

        Alice->receiveQueueIndex++;
        Bob->previousSendQueueIndex++;

        /* Alice is now processing the Bob's DHPart 2 */
        retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

        Alice->previousReceiveQueueIndex++;

        /* Checking if the sending was good or not */
        if (retval)
        {
            printf("Mistake about the sending of Bob's DHPart 2 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Put the Confirm 1 of Alice in the Bob's queue */
        Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

        for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
        {
            Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
        }

        Alice->previousSendQueueIndex++;
        Bob->receiveQueueIndex++;

        /* Bob is now processing the Confirm 1 message of Alice */  
        retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

        Bob->previousReceiveQueueIndex++;

        /* Checking if the sending of Alice's Confirm 1 is good or not */
        if (retval)
        {
            printf("Mistake about the sending of Alice's Confirm 1 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Update the Confirm 2 of Bob */
        retval = bzrtp_packetUpdateSequenceNumber(contextBob->channelContext[BobSSRC]->selfPackets[CONFIRM_MESSAGE_STORE_ID], contextBob->channelContext[BobSSRC]->selfSequenceNumber);

        /* Checking if the update was good or not */
        if (retval)
        {
            printf("Mistake about update of Bob's Confirm 2 : %d\n", retval);
            return ERROR_UPDATE_PACKET;
        }

        /* Put the Bob's Confirm 1 in the Alice's queue */
        Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (contextBob->channelContext[BobSSRC]->selfPackets[CONFIRM_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_HEADER_LENGTH + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);

        for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
        {
            Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = contextBob->channelContext[BobSSRC]->selfPackets[CONFIRM_MESSAGE_STORE_ID]->packetString[i];
        }

        Alice->receiveQueueIndex++;
        Bob->previousSendQueueIndex++;

        /* Alice is now processing the Confirm of Bob */
        retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

        Alice->previousReceiveQueueIndex++;

        /* Checking if the sending of Bob's Confirm 2 is good or not */ 
        if (retval)
        {
            printf("Mistake about the sending of Bob's Confirm 2 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Put the Alice's Conf2Ack in the Bob's queue */
        Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

        for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
        {
            Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
        }

        Bob->receiveQueueIndex++;
        Alice->previousSendQueueIndex++;

        /* Bob is now processing the Conf2Ack of Alice */
        retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

        Bob->previousReceiveQueueIndex++;

        /* Checking if the sending of Alice's Conf2Ack is good or not */
        if (retval)
        {
            printf("Mistake about the sending of Alice's Conf2Ack : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        printf("SRTP sessions begin\n");

        /* Checking if the secrets are the same */
        retval = compareSecrets(&contextAlice->channelContext[AliceSSRC]->srtpSecrets, &contextBob->channelContext[BobSSRC]->srtpSecrets, TRUE);

        if (retval == 0)
        {
            printf("The SRTP secrets are the same\n");
        }
        else
            printf("Erreur dans : %d\n", retval);
    }
    else
    {
        printf("Bob is responder and Alice is Initiator\n");

        Alice->previousSendQueueIndex--;

        /* Put the Alice's Commit in the queue of Bob */
        Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

        for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
        {
            Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
        }

        Alice->previousSendQueueIndex++;
        Bob->receiveQueueIndex++;

        /* Bob is now processing the Alice's Commit message and turn into responder */
        retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

        Bob->previousReceiveQueueIndex++;

        /* Checking if the sending of Alice's Commit was good or not */
        if (retval)
        {
            printf("Mistake about the sending of Alice's Commit : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Update the DHPart 1 of Bob */
        retval = bzrtp_packetUpdateSequenceNumber(contextBob->channelContext[BobSSRC]->selfPackets[DHPART_MESSAGE_STORE_ID], contextBob->channelContext[BobSSRC]->selfSequenceNumber);

        /* Checking if the update was good or not */
        if (retval)
        {
            printf("Mistake about the update of DHPart 1 of Bob : %d\n", retval);
            return ERROR_UPDATE_PACKET;
        }

        /* Put the DHPart 1 of Bob in the Alice queue */
        Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (contextBob->channelContext[BobSSRC]->selfPackets[DHPART_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_HEADER_LENGTH + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);

        for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
        {
            Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = contextBob->channelContext[BobSSRC]->selfPackets[DHPART_MESSAGE_STORE_ID]->packetString[i];
        }

        Bob->previousSendQueueIndex++;
        Alice->receiveQueueIndex++;

        /* Alice is now processing the Bob's DHPart 1 message */
        retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

        Alice->previousReceiveQueueIndex++;

        /* Checking if the sending of Bob's DHPart 1 was good or not */
        if (retval)
        {
            printf("Mistake about the DHPart 1's sending of Bob : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Put the DHPart 2 of Alice int the Bob queue */
        Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

        for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
        {
            Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
        }

        Bob->receiveQueueIndex++;
        Alice->previousSendQueueIndex++;


        /* Bob is now processing the Alice's DHPart 2 message */
        retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

        Bob->previousReceiveQueueIndex++;

        /* Checking if the sending of Alice's DHPart 2 message was good or not */
        if (retval)
        {
            printf("Mistake about the sending of Alice's DHPart 2 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Update the Confirm 1 packet of Bob */
        retval = bzrtp_packetUpdateSequenceNumber(contextBob->channelContext[BobSSRC]->selfPackets[CONFIRM_MESSAGE_STORE_ID], contextBob->channelContext[BobSSRC]->selfSequenceNumber);

        /* Checking if the update was good or not */
        if (retval)
        {
            printf("Mistake about the update of Bob's Confirm 1 : %d\n", retval);
            return ERROR_UPDATE_PACKET;
        }

        /* Put the Confirm 1 of Bob in the Alice queue */
        Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (contextBob->channelContext[BobSSRC]->selfPackets[CONFIRM_MESSAGE_STORE_ID]->messageLength + ZRTP_PACKET_HEADER_LENGTH + ZRTP_PACKET_CRC_LENGTH) * sizeof(uint8_t);

        for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
        {
            Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = contextBob->channelContext[BobSSRC]->selfPackets[CONFIRM_MESSAGE_STORE_ID]->packetString[i];
        }

        Alice->receiveQueueIndex++;
        Bob->previousSendQueueIndex++;

        /* Alice is now processing the Confirm 1 of Bob */
        retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

        Alice->previousReceiveQueueIndex++;

        /* Checking if the sending of Bob's Confirm 1 was good or not */
        if (retval)
        {
            printf("Mistake about the sending of Bob's Confirm 1 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Put the Alice's Confirm 2 in the Bob queue */
        Bob->receiveQueue[Bob->receiveQueueIndex].packetLength = Alice->sendQueue[Alice->previousSendQueueIndex].packetLength;

        for (int i = 0; i < Bob->receiveQueue[Bob->receiveQueueIndex].packetLength; i++)
        {
            Bob->receiveQueue[Bob->receiveQueueIndex].packetString[i] = Alice->sendQueue[Alice->previousSendQueueIndex].packetString[i];
        }

        Bob->receiveQueueIndex++;
        Alice->previousSendQueueIndex++;

        /* Bob is now processing the Alice's Confirm 2 */
        retval = bzrtp_processMessage(contextBob, BobSSRC, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetString, Bob->receiveQueue[Bob->previousReceiveQueueIndex].packetLength);

        Bob->previousReceiveQueueIndex++;

        /* Checking if the sending of Alice's Confirm 2 was good or not */
        if (retval)
        {
            printf("Mistake about the sending of Alice's Confirm 2 : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        /* Recreate the Conf2Ack packet because of a problem of sequence number */
        bzrtpPacket_t * conf2AckPacket = bzrtp_createZrtpPacket(contextBob, contextBob->channelContext[BobSSRC], MSGTYPE_CONF2ACK, &retval);

        /* Checking if the creation was good or not */
        if (retval)
        {
            printf("Mistake about the creation of Conf2Ack packet of Bob : %d\n", retval);
            return retval;
        }

        /* Build of the Conf2Ack packet */
        retval = bzrtp_packetBuild(contextBob, contextBob->channelContext[BobSSRC], conf2AckPacket, contextBob->channelContext[BobSSRC]->selfSequenceNumber);

        /* Checking if the build of the Conf2Ack packet was good or not */
        if (retval)
        {
            printf("Mistake about the build of the Conf2Ack packet : %d\n", retval);
            return ERROR_PACKET_BUILD;
        }

        /* Put Conf2Ack packet of Bob's Conf2Ack */
        Alice->receiveQueue[Alice->receiveQueueIndex].packetLength = (conf2AckPacket->messageLength + ZRTP_PACKET_OVERHEAD) * sizeof(uint8_t);

        for (int i = 0; i < Alice->receiveQueue[Alice->receiveQueueIndex].packetLength; i++)
        {
            Alice->receiveQueue[Alice->receiveQueueIndex].packetString[i] = conf2AckPacket->packetString[i];
        }

        Alice->receiveQueueIndex++;
        Bob->previousSendQueueIndex++;

        /* Alice is now processing the Bob's Conf2Ack */
        retval = bzrtp_processMessage(contextAlice, AliceSSRC, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetString, Alice->receiveQueue[Alice->previousReceiveQueueIndex].packetLength);

        Alice->previousReceiveQueueIndex++;

        /* CHecking if the sending of the Bob's Conf2Ack was good or not */
        if (retval)
        {
            printf("Erreur dans l'envoi du Conf2Ack de Bob : %d\n", retval);
            return ERROR_PROCESS_MESSAGE;
        }

        printf("SRTP sessions begin\n");

        /* Checking if the secrets are the same */
        retval = compareSecrets(&contextAlice->channelContext[AliceSSRC]->srtpSecrets, &contextBob->channelContext[BobSSRC]->srtpSecrets, TRUE);

        if (retval == 0)
        {
            printf("The SRTP secrets are the same\n");
        }
        else
            printf("Erreur dans : %d\n", retval);

        bzrtp_freeZrtpPacket(conf2AckPacket);
    }

    free(cbs);

    destroyClient(Alice);
    destroyClient(Bob);

    bzrtp_destroyBzrtpContext(contextAlice, AliceSSRC);
    bzrtp_destroyBzrtpContext(contextBob, BobSSRC);

    return 0;
}