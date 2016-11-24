#include <Windows.h>
#include "APE.h"

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
int Write2Pipe(char *pData, int pDataLen);
void HandleHTTPTraffic(char *pSrcMAC, PIPHDR pIPHdr, PTCPHDR pTCPHdr);


#endif
