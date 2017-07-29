#pragma once

#include <Windows.h>
#include "APESniffer.h"


int ModeMinaryStart(PSCANPARAMS pScanParams);
void SniffAndParseCallback(unsigned char *pScanParams, struct pcap_pkthdr *pPcapHdr, unsigned char *pPktData);
int WriteOutput(char *pData, int pDataLen);
void HandleHttpTraffic(char *pSrcMAC, PIPHDR pIPHdr, PTCPHDR pTCPHdr);