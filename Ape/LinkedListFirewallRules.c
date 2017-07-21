#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <Shlwapi.h>

#include "APE.h"
#include "NetworkHelperFunctions.h"
#include "LinkedListFirewallRules.h"
#include "Logging.h"


extern CRITICAL_SECTION gCSFirewallRules;



PRULENODE InitFirewallRules()
{
  PRULENODE listTail = NULL;

  if ((listTail = (PRULENODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RULENODE))) != NULL)
  {
    listTail->isTail = TRUE;
    listTail->next = NULL;
    listTail->prev = NULL;
  }

  return listTail;
}



void AddRuleToList(PPRULENODE listHead, PRULENODE newRule)
{
  if (newRule == NULL)
  {
    goto END;
  }

  newRule->prev = NULL;
  newRule->isTail = FALSE;
  newRule->next = *listHead;

  // Set the new record at the head of the list
  ((PRULENODE)*listHead)->prev = newRule;
  *listHead = newRule;

END:

  return;
}



int FirewallRulesCountNodes(PRULENODE allConNodesParam)
{
  int retVal = 0;

  while (allConNodesParam != NULL)
  {
    allConNodesParam = allConNodesParam->next;
    retVal++;
  }

  return retVal;
}


void PrintAllFirewallRulesNodes(PRULENODE allFirewallRuleNodes)
{
  PRULENODE tmpRule;

  for (tmpRule = allFirewallRuleNodes; tmpRule != NULL && tmpRule->isTail == FALSE; tmpRule = tmpRule->next)
  {
    LogMsg(DBG_INFO, "AddToSystemsList():  %s %s:(%d-%d) -> %s:(%d-%d)   %d\n",
      tmpRule->Protocol, tmpRule->SrcIPStr, tmpRule->SrcPortLower,
      tmpRule->SrcPortUpper, tmpRule->DstIPStr, tmpRule->DstPortLower,
      tmpRule->DstPortUpper, tmpRule->isTail);
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

  for (; firewallRuleNodesParam != NULL && firewallRuleNodesParam->isTail == FALSE; firewallRuleNodesParam = firewallRuleNodesParam->next)
  {
    // 1. Protocol
    if (protocolParam != NULL && strncmp(protocolParam, firewallRuleNodesParam->Protocol, 4))
    {
      continue;
    }

    // 2. Source IP      
    if (firewallRuleNodesParam->SrcIPBin != 0 && srcIpParam != firewallRuleNodesParam->SrcIPBin)
    {
      continue;
    }

    // 3. Source port

    if ((firewallRuleNodesParam->SrcPortLower != 0 && firewallRuleNodesParam->SrcPortUpper != 0) && (srcPortParam < firewallRuleNodesParam->SrcPortLower || srcPortParam > firewallRuleNodesParam->SrcPortUpper))
    {
      continue;
    }

    // 4. Destination IP      
    if (firewallRuleNodesParam->DstIPBin != 0 && dstIpParam != firewallRuleNodesParam->DstIPBin)
    {
      continue;
    }

    // 5. Destination port      
    if ((firewallRuleNodesParam->DstPortLower != 0 && firewallRuleNodesParam->DstPortUpper != 0) && (dstPortParam < firewallRuleNodesParam->DstPortLower || dstPortParam > firewallRuleNodesParam->DstPortUpper))
    {
      continue;
    }

    retVal = firewallRuleNodesParam;
    break;
  }

END:

  return retVal;
}
