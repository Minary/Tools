#pragma once

#include <windows.h>
#include "LinkedListTargetSystems.h"


typedef struct
{
  u_char *pcapData;
  unsigned int pcapDataLen;
  PETHDR etherHdr;
  PIPHDR ipHdr;
  PTCPHDR tcpHdr;
  PUDPHDR udpHdr;
  int ipHdrLen;
  unsigned char srcIp[MAX_BUF_SIZE + 1];
  unsigned long srcIpBin;
  unsigned char dstIp[MAX_BUF_SIZE + 1];
  unsigned long dstIpBin;
  unsigned short dstPort;
  unsigned short srcPort;
  char proto[128];
  unsigned short pktLen;
  char suffix[MAX_BUF_SIZE + 1];
  char logMsg[MAX_BUF_SIZE + 1];
} 
PACKET_INFO, *PPACKET_INFO;



void PacketForwarding_handler(u_char *param, const struct pcap_pkthdr *pktHeader, const u_char *data);
DWORD WINAPI ForwardPackets(LPVOID lpParam);
void PrepareDataPacketStructure(u_char *data, PPACKET_INFO packetInfo);
void ProcessData2GW(PPACKET_INFO packetInfo, PSCANPARAMS scanParams);
void ProcessData2Internet(PPACKET_INFO packetInfo, PSCANPARAMS scanParams);
void ProcessFirewalledData(PPACKET_INFO packetInfo, PSCANPARAMS scanParams);
void ProcessData2Victim(PPACKET_INFO packetInfo, PSYSNODE realDstSys, PSCANPARAMS scanParams);
