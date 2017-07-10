#pragma once

#define BIN_IP_LEN 4
#define MINI_BUF_LEN 256

/*
 * Type declarations.
 *
 */
//#pragma pack(push, 1)
typedef struct RULENODESTRUCT
{
  int first;

//  char SrcIPBin[BIN_IP_LEN];
  unsigned long SrcIPBin;
  char SrcIPStr[MAX_IP_LEN + 1];
//  char DstIPBin[BIN_IP_LEN];
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
//#pragma pack(pop)


PRULENODE InitFirewallRules();
void AddRuleToList(PPRULENODE pRuleNodes, PRULENODE pTmpRuleNode);
//PRULENODE RuleNodeExists(PRULENODE allConNodesParam, char *nodeIdParam);
int FirewallRulesCountNodes(PRULENODE allConNodesParam);
void PrintAllFirewallRulesNodes(PRULENODE allFirewallRuleNodes);
PRULENODE FirewallBlockRuleMatch(PRULENODE firewallRuleNodesParam, char *protocolParam, unsigned long srcIpParam, unsigned long dstIpParam, unsigned short srcPortParam, unsigned short dstPortParam);
