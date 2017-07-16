#pragma once

#include <Windows.h>
#include "APE.h"

DWORD WINAPI StartArpPoisoning(LPVOID pScanParams);
DWORD WINAPI ArpDePoisoning(LPVOID pScanParams);
//int SendArpPacket(pcap_t *pIFCHandle, PArpPacket pARPPacket);
int SendArpPacket(void *interfaceHandleParam, PArpPacket arpPacketParam);
int SendArpPoison(PSCANPARAMS scanParamsParam, unsigned char victimMacBinParam[BIN_MAC_LEN], unsigned char victimIpBinParam[BIN_IP_LEN]);
