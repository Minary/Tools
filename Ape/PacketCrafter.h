#ifndef __PACKETCRAFTER__
#define __PACKETCRAFTER__


#include <Windows.h>
#include "LinkedListSpoofedDnsHosts.h"


/*
 * Type definitions
 *
 */




/*
 * Function forward declarations
 *
 */
int buildSpoofedDnsReplyPacket(unsigned char *pRawPacket, int pRawPacketLen, PHOSTNODE pNode, char *pOutputBuffer, int *pOutputBufferLen);
void GenerateEtherPacket(unsigned char * pPacket, unsigned char * pDest, unsigned char * pSource);
void GenerateUdpPacket(unsigned char * pPacket, unsigned short pUDPPacketLength, unsigned short pSPort, unsigned short pDPort);
void GenerateDnsPacket(unsigned char * pPacket, unsigned char * pDNSURLA, unsigned short pDNSURLALength, unsigned short lTransactionID, char *pSpoofedIP);
void GenerateIpPacket(unsigned char *pPacket, unsigned char pIPProtocol, IPADDRESS pSaddr, IPADDRESS pDaddr, unsigned short pDNSPacketSize);
unsigned short in_cksum(unsigned short * pAddr, int iLen);

#endif