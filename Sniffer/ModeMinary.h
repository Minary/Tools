#pragma once

#include <Windows.h>
#include "Sniffer.h"


int ModeMinaryStart(PSCANPARAMS scanParamsParam);
void SniffAndParseCallback(unsigned char *scanParamsParam, struct pcap_pkthdr *pcapHdrParam, unsigned char *packetDataParam);
int WriteOutput(char *data, int dataLength);
void HandleHttpTraffic(char *srcMacStrParam, PIPHDR ipHdrPtrParam, PTCPHDR tcpHdrPtrParam);
BOOL GetPcapDevice();
int FilterException(int code, PEXCEPTION_POINTERS ex);
u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count);
void ChangeToDnsNameFormat(unsigned char*, unsigned char*, int outputlen);
void GetHostResolution(unsigned char* udpHdrPtr, char *hostRes[]);