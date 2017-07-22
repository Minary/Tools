#pragma once

#include <Windows.h>
#include "APE.h"

DWORD WINAPI ArpPoisoningLoop(LPVOID pScanParams);
DWORD WINAPI ArpDePoisoning(LPVOID pScanParams);
BOOL SendArpPacket(void *interfaceHandleParam, PArpPacket arpPacketParam);
int SendArpPoison(PSCANPARAMS scanParamsParam, unsigned char victimMacBinParam[BIN_MAC_LEN], unsigned char victimIpBinParam[BIN_IP_LEN]);
