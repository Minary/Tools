#pragma once

#include <Windows.h>
#include "LinkedListSpoofedDnsHosts.h"

int BuildSpoofedDnsReplyPacket(unsigned char *pRawPacket, int pRawPacketLen, PHOSTNODE pNode, char *pOutputBuffer, int *pOutputBufferLen);
void GenerateEthernetPacket(unsigned char * pPacket, unsigned char * pDest, unsigned char * pSource);
void GenerateIpPacket(unsigned char *pPacket, unsigned char pIPProtocol, IPADDRESS pSaddr, IPADDRESS pDaddr, unsigned short pDNSPacketSize);
void GenerateUdpPacket(unsigned char * pPacket, unsigned short pUDPPacketLength, unsigned short pSPort, unsigned short pDPort);
unsigned short in_cksum(unsigned short * pAddr, int iLen);
