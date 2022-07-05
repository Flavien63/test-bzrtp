#ifndef MAIN_H
#define MAIN_H

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

#define ERROR_CREATE_CONTEXT 0x01
#define ERROR_INIT_CONTEXT 0x02
#define ERROR_INIT_CLIENT 0x03
#define ERROR_START_CHANNEL 0x04
#define ERROR_PROCESS_MESSAGE 0x05
#define ERROR_INIT_CALLBACKS 0x06
#define ERROR_INIT_CLIENTDATA 0x07
#define ERROR_UPDATE_PACKET 0x08
#define ERROR_PACKET_BUILD 0x09

int sendData(void * clientData, const uint8_t * packetString, uint16_t packetLength);

int compareSecrets(bzrtpSrtpSecrets_t *a, bzrtpSrtpSecrets_t* b, uint8_t mainChannel);

int main(int args, char *argv[]);

#endif