#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "APE.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "Logging.h"



PHOSTNODE InitHostsList()
{
  PHOSTNODE listTail = NULL;

  if ((listTail = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
  {
    listTail->isTail = TRUE;
    listTail->next = NULL;
    listTail->prev = NULL;
  }

  return listTail;
}


void AddSpoofedIpToList(PPHOSTNODE listHead, unsigned char *hostNameParam, unsigned char *spoofedIpParam)
{
  PHOSTNODE tmpNode = NULL;

  if ((tmpNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
  {
    CopyMemory(tmpNode->HostData.HostName, hostNameParam, sizeof(tmpNode->HostData.HostName) - 1);
    CopyMemory(tmpNode->HostData.SpoofedIP, spoofedIpParam, sizeof(tmpNode->HostData.SpoofedIP) - 1);
    tmpNode->HostData.type = RESP_A;
    tmpNode->prev = NULL;
    tmpNode->isTail = FALSE;

    // Insert new record at the beginning of the list
    tmpNode->next = (PHOSTNODE) *listHead;
    ((PHOSTNODE)*listHead)->prev = (PHOSTNODE) tmpNode;
    *listHead = tmpNode;
  }
}


void AddSpoofedCnameToList(PPHOSTNODE listHead, unsigned char *hostNameParam, unsigned char *cnameHost, unsigned char *spoofedIpParam)
{
  PHOSTNODE tmpNode = NULL;

  if ((tmpNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
  {
    CopyMemory(tmpNode->HostData.HostName, hostNameParam, sizeof(tmpNode->HostData.HostName) - 1);
    CopyMemory(tmpNode->HostData.CnameHost, cnameHost, sizeof(tmpNode->HostData.CnameHost) - 1);
    CopyMemory(tmpNode->HostData.SpoofedIP, spoofedIpParam, sizeof(tmpNode->HostData.SpoofedIP) - 1);
    tmpNode->HostData.type = RESP_CNAME;
    tmpNode->prev = NULL;
    tmpNode->isTail = FALSE;

    // Insert new record at the beginning of the list
    tmpNode->next = (PHOSTNODE) *listHead;
    ((PHOSTNODE)*listHead)->prev = (PHOSTNODE) tmpNode;
    *listHead = tmpNode;
  }
}


PHOSTNODE GetNodeByHostname(PHOSTNODE sysNodesParam, unsigned char *hostnameParam)
{
  PHOSTNODE retVal = NULL;
  PHOSTNODE tmpSys;
  int count = 0;

  if ((tmpSys = sysNodesParam) == NULL)
  {
    goto END;
  }

  // Go to the end of the list
  for (count = 0; count < MAX_NODE_COUNT; count++)
  {
    if (tmpSys != NULL &&
        !strncmp((char *) tmpSys->HostData.HostName, (char *) hostnameParam, sizeof(tmpSys->HostData.HostName) - 1))
    {
      retVal = tmpSys;
      break;
    }

    if ((tmpSys = (PHOSTNODE)tmpSys->next) == NULL)
    {
      break;
    }
  }

END:

  return retVal;
}



void PrintDnsSpoofingRulesNodes(PHOSTNODE listHead)
{
  PHOSTNODE listPos;

  for (listPos = listHead; listPos != NULL && listPos->isTail == FALSE; listPos = listPos->next)
  {
    if (listPos->HostData.type == RESP_A)
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): Type:A\t%s -> %s", listPos->HostData.HostName, listPos->HostData.SpoofedIP);
    }
    else if (listPos->HostData.type == RESP_CNAME)
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): Type:CNAME\t%s -> %s -> %s", listPos->HostData.HostName, listPos->HostData.CnameHost, listPos->HostData.SpoofedIP);
    }
    else
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): INVALID\t%s -> %s", listPos->HostData.HostName, listPos->HostData.SpoofedIP);
    }
  }
}

