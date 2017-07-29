#include <Windows.h>
#include "APESniffer.h"

#ifndef __SNIFFANDEVALUATE__
#define __SNIFFANDEVALUATE__


/*
 * Type definitions
 *
 */



/*
 * Function forward declarations
 *
 */
int StartSniffAndEvaluate(PSCANPARAMS pScanParams);
void SniffAndParseCallback(unsigned char *pScanParams, struct pcap_pkthdr *pPcapHdr, unsigned char *pPktData);
int WriteOutput(char *pData, int pDataLen);
void HandleHTTPTraffic(char *pSrcMAC, PIPHDR pIPHdr, PTCPHDR pTCPHdr);
int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam);

#endif