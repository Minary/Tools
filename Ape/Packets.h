#ifndef __PACKETCAPTURES__
#define __PACKETCAPTURES__

#include <windows.h>
//#include "APE.h"

DWORD WINAPI ArpDePoisoning(LPVOID pScanParams);

DWORD WINAPI CaptureARPReplies (LPVOID lpParam);
void ARPReplies_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

DWORD WINAPI ForwardPackets(LPVOID lpParam);
void AllIncomingPacketsSniffer_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

DWORD WINAPI ScanNetwork(LPVOID lpParam);
int SendARPWhoHas(PSCANPARAMS pScanParams, unsigned long lIPAddress);
int SendArpPoison(PSCANPARAMS pScanParams, unsigned char pVictimMAC[6], unsigned char pVictimIP[4]);
int SendArpPacket(pcap_t *pIFCHandle, PArpPacket pARPPacket);

#endif