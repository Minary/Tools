#pragma once

#include "RouterIPv4.h"

typedef struct
{
  char TimeStamp[MAX_BUF_SIZE + 1];
  unsigned char sysMacBin[BIN_MAC_LEN];
  unsigned char sysIpStr[MAX_IP_LEN + 1];
  unsigned char sysIpBin[BIN_IP_LEN];
} SYSDATA, *PSYSDATA;


typedef struct SYSNODE
{
  SYSDATA data;

  BOOL isTail;
  struct SYSNODE *prev;
  struct SYSNODE *next;
} SYSNODE, *PSYSNODE, **PPSYSNODE;


PSYSNODE InitSystemList();
int GetListCopy(PSYSNODE pNodes, PSYSTEMNODE pSysArray);
void ClearSystemList(PPSYSNODE listHead);
void AddToSystemsList(PPSYSNODE pSysNodes, unsigned char pSysMAC[BIN_MAC_LEN], char *pSysIP, unsigned char pSysIPBin[BIN_IP_LEN]);
PSYSNODE GetNodeByIp(PSYSNODE pSysNodes, unsigned char pIPBin[BIN_IP_LEN]);
PSYSNODE GetNodeByMac(PSYSNODE pSysNodes, unsigned char pMAC[BIN_MAC_LEN]);
void PrintTargetSystems(PSYSNODE listHead);
