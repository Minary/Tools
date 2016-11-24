#ifndef __NETWORKFUNCTIONS__
#define __NETWORKFUNCTIONS__

#include <Windows.h>
#include <iphlpapi.h>

#include "APESniffer.h"


void Mac2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);
void Ip2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen);
void String2Mac(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pInput, int pInputLen);
int String2Ip(unsigned char pIP[BIN_IP_LEN], unsigned char *pInput, int pInputLen);
int GetAliasByIfcIndex(int pIfcIndex, char *pAliasBuf, int pBufLen);
void SetMacStatic(char *pIfcAlias, char *pIP, char *pMAC);
void RemoveMac(char *pIfcAlias, char *pIPAddr);
void DumpPacket(unsigned char *pPktData, int pPktLen, char *pTitlestring, const struct pcap_pkthdr *pPktHdr);

#endif
