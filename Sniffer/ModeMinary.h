#pragma once

#include <Windows.h>
#include "Sniffer.h"


int ModeMinaryStart(PSCANPARAMS scanParamsParam);
void SniffAndParseCallback(unsigned char *scanParamsParam, struct pcap_pkthdr *pcapHdrParam, unsigned char *packetDataParam);
int WriteOutput(char *data, int dataLength);
void HandleHttpTraffic(char *srcMacStrParam, PIPHDR ipHdrPtrParam, PTCPHDR tcpHdrPtrParam);
BOOL GetPcapDevice();