#ifndef __PACKETCRAFTER2__
#define __PACKETCRAFTER2__


#include <Windows.h>


/*
 * Function forward declaration.
 *
 */
void *DnsRequestPoisonerGetHost2Spoof(u_char *pData);
unsigned char* dns2Text2(unsigned char* reader, unsigned char* buffer, int *count);
void InjectDNSPacket(unsigned char * in_pPacket, pcap_t* device_descriptor, char *pSpoofedIP, char *pSourceIP, char *pDestIP, char *pHostName);
void GenerateEtherPacket2(unsigned char * pPacket, unsigned char * pDest, unsigned char * pSource);
void GenerateIPPacket2(unsigned char *pPacket, unsigned char pIPProtocol, IPADDRESS pSaddr, IPADDRESS pDaddr, unsigned short pDNSPacketSize);
void GenerateDNSPacket2(unsigned char * pPacket, unsigned short pDNSHdrLength, unsigned char * pDNSURLA, unsigned short lTransactionID, char *pSpoofedIP);
void GenerateUDPPacket2(unsigned char * pPacket, unsigned short pUDPPacketLength, unsigned short pSrcPort, unsigned short pDstPort);
unsigned short in_cksum2(unsigned short * pAddr, int pLength);


#endif