#pragma once

#include "RouterIPv4.h"

#define BIN_IP_LEN 4
#define MINI_BUF_LEN 256

/*
* Type declarations.
*
*/

typedef struct RULENODESTRUCT
{
  BOOL isTail;

  unsigned long SrcIPBin;
  char SrcIPStr[MAX_IP_LEN + 1];
  unsigned long DstIPBin;
  char DstIPStr[MAX_IP_LEN + 1];

  unsigned short SrcPortLower;
  unsigned short SrcPortUpper;
  unsigned short DstPortLower;
  unsigned short DstPortUpper;
  char Protocol[MINI_BUF_LEN + 1];
  char Descr[256];

  struct RULENODESTRUCT *prev;
  struct RULENODESTRUCT *next;
} RULENODE, *PRULENODE, **PPRULENODE;


PRULENODE InitFirewallRules();
void AddRuleToList(PPRULENODE listHead, PRULENODE pTmpRuleNode);
int FirewallRulesCountNodes(PRULENODE allConNodlistHeadesParam);
void PrintAllFirewallRulesNodes(PRULENODE listHead);
PRULENODE FirewallBlockRuleMatch(PRULENODE listHead, char *protocolParam, unsigned long srcIpParam, unsigned long dstIpParam, unsigned short srcPortParam, unsigned short dstPortParam);
