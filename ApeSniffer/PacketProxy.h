
#ifndef __PACKETPROXY__
#define __PACKETPROXY__

#include <windows.h>
//#include "PacketCrafter.h"
#include "APESniffer.h"

/*
* Type definitions
*
*/




/*
* Function forward declarations
*
*/
DWORD WINAPI StartPacketProxy(LPVOID pScanParams);
void ResendCallback(unsigned char *param, struct pcap_pkthdr *header, unsigned char *pkt_data);
int ResendPacket(PSCANPARAMS pScanParams, unsigned char *pPktData, int pPktLen);
void PacketForwarding_handler(u_char *param, const struct pcap_pkthdr *pPktHeader, const u_char *pData);

#endif