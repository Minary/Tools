#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <Shlwapi.h>


#include "APE.h"
#include "NetworkHelperFunctions.h"
#include "LinkedListFirewallRules.h"

extern CRITICAL_SECTION gCSFirewallRules;



PRULENODE InitFirewallRules()
{
  PRULENODE firstSysNode = NULL;

  //  EnterCriticalSection(&gCSFirewallRules);
  if ((firstSysNode = (PRULENODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RULENODE))) != NULL)
  {
    firstSysNode->first = 1;
    firstSysNode->next = NULL;
    firstSysNode->prev = NULL;
  }

  //  LeaveCriticalSection(&gCSFirewallRules);

  return firstSysNode;
}



void AddRuleToList(PPRULENODE ruleNodesParam, PRULENODE newRuleNodeParam)
{
  if (newRuleNodeParam != NULL)
  {
    newRuleNodeParam->prev = NULL;
    newRuleNodeParam->first = 0;
    newRuleNodeParam->next = *ruleNodesParam;
    ((PRULENODE)*ruleNodesParam)->prev = newRuleNodeParam;
    *ruleNodesParam = newRuleNodeParam;
  }
}



int FirewallRulesCountNodes(PRULENODE allConNodesParam)
{
  int retVal = 0;

//  EnterCriticalSection(&gCSFirewallRules);
  while (allConNodesParam != NULL)
  {
    allConNodesParam = allConNodesParam->next;
    retVal++;
  }
  
//  EnterCriticalSection(&gCSFirewallRules);

  return retVal;
}


void PrintAllFirewallRulesNodes(PRULENODE allFirewallRuleNodes)
{
  while (allFirewallRuleNodes != NULL && allFirewallRuleNodes->first == 0)
  {
    printf("%s %s:(%d-%d) -> %s:(%d-%d)   %d\n", allFirewallRuleNodes->Protocol, allFirewallRuleNodes->SrcIPStr, allFirewallRuleNodes->SrcPortLower, allFirewallRuleNodes->SrcPortUpper, allFirewallRuleNodes->DstIPStr, allFirewallRuleNodes->DstPortLower, allFirewallRuleNodes->DstPortUpper, allFirewallRuleNodes->first);
    allFirewallRuleNodes = allFirewallRuleNodes->next;
  }
}


PRULENODE FirewallBlockRuleMatch(PRULENODE firewallRuleNodesParam, char *protocolParam, unsigned long srcIpParam, unsigned long dstIpParam, unsigned short srcPortParam, unsigned short dstPortParam)
{
  PRULENODE retVal = NULL;
  char *srcIpStr = NULL;
  char *ruleIpSrcStr = NULL;

  if (firewallRuleNodesParam == NULL)
  {
    goto END;
  }

  for (; firewallRuleNodesParam != NULL && firewallRuleNodesParam->first == 0; firewallRuleNodesParam = firewallRuleNodesParam->next)
  {
    // 1. Protocol
    if (protocolParam != NULL && strncmp(protocolParam, firewallRuleNodesParam->Protocol, 4))
      continue;

    // 2. Source IP      
    if (firewallRuleNodesParam->SrcIPBin != 0 && srcIpParam != firewallRuleNodesParam->SrcIPBin)
      continue;

    // 3. Source port

    if ((firewallRuleNodesParam->SrcPortLower != 0 && firewallRuleNodesParam->SrcPortUpper != 0) && (srcPortParam < firewallRuleNodesParam->SrcPortLower || srcPortParam > firewallRuleNodesParam->SrcPortUpper))
      continue;

    // 4. Destination IP      
    if (firewallRuleNodesParam->DstIPBin != 0 && dstIpParam != firewallRuleNodesParam->DstIPBin)
      continue;

    // 5. Destination port      
    if ((firewallRuleNodesParam->DstPortLower != 0 && firewallRuleNodesParam->DstPortUpper != 0) && (dstPortParam < firewallRuleNodesParam->DstPortLower || dstPortParam > firewallRuleNodesParam->DstPortUpper))
      continue;

    retVal = firewallRuleNodesParam;
    break;
  }

END:

  return retVal;
}
