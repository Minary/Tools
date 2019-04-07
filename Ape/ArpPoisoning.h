#pragma once

#include <Windows.h>
#include "APE.h"

DWORD ArpPoisoningLoop(PSCANPARAMS pScanParams);
DWORD ArpDePoisoning(PSCANPARAMS pScanParams);
BOOL SendArpPacket(void *interfaceHandleParam, PArpPacket arpPacketParam);
BOOL SendArpPoison(PSCANPARAMS scanParamsParam, unsigned char victimMacBinParam[BIN_MAC_LEN], unsigned char victimIpBinParam[BIN_IP_LEN]);
BOOL APE_ControlHandler(DWORD idParam);
