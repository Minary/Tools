#pragma once

#include <Windows.h>
#include <iphlpapi.h>


void MacBin2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);
void IpBin2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen);
void MacString2Bin(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pInput, int pInputLen);
int IpString2Bin(unsigned char pIP[BIN_IP_LEN], unsigned char *pInput, int pInputLen);
BOOL GetAliasByIfcIndex(int pIfcIndex, char *pAliasBuf, int pBufLen);
void SetMacStatic(char *pIfcAlias, char *pIP, char *pMAC);
void RemoveMacFromCache(char *pIfcAlias, char *pIPAddr);
void DumpPacket(unsigned char *pPktData, int pPktLen, char *pTitlestring, const struct pcap_pkthdr *pPktHdr);
unsigned short in_cksum(unsigned short * addr, int length);