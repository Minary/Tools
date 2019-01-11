#include <windows.h>
#include <shlwapi.h>
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

  if ((tmpNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) == NULL)
  {
    return;
  }

  CopyMemory(tmpNode->Data.HostName, hostNameParam, sizeof(tmpNode->Data.HostName) - 1);
  CopyMemory(tmpNode->Data.SpoofedIp, spoofedIpParam, sizeof(tmpNode->Data.SpoofedIp) - 1);
  if (tmpNode->Data.HostName[0] == '*')
  {
    FillInWildcardHostname(tmpNode);
  }

  tmpNode->Data.Type = RESP_A;
  tmpNode->prev = NULL;
  tmpNode->isTail = FALSE;

  // Insert new record at the beginning of the list
  tmpNode->next = (HOSTNODE *)*listHead;
  ((PHOSTNODE)*listHead)->prev = (HOSTNODE *)tmpNode;
  *listHead = tmpNode;
}


void AddSpoofedCnameToList(PPHOSTNODE listHead, unsigned char *hostNameParam, unsigned char *cnameHostParam, unsigned char *spoofedIpParam)
{
  PHOSTNODE tmpNode = NULL;

  if ((tmpNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) == NULL)
  {
    return;
  }

  CopyMemory(tmpNode->Data.HostName, hostNameParam, sizeof(tmpNode->Data.HostName) - 1);
  CopyMemory(tmpNode->Data.CnameHost, cnameHostParam, sizeof(tmpNode->Data.CnameHost) - 1);
  CopyMemory(tmpNode->Data.SpoofedIp, spoofedIpParam, sizeof(tmpNode->Data.SpoofedIp) - 1);
  if (tmpNode->Data.HostName[0] == '*')
  {
    FillInWildcardHostname(tmpNode);
  }

  tmpNode->Data.Type = RESP_CNAME;
  tmpNode->prev = NULL;
  tmpNode->isTail = FALSE;

  // Insert new record at the beginning of the list
  tmpNode->next = (HOSTNODE *)*listHead;
  ((PHOSTNODE)*listHead)->prev = (HOSTNODE *)tmpNode;
  *listHead = tmpNode;
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
    // Break if current hostname equals the hostname in the list
    if (tmpSys != NULL &&
        !strncmp((char *) tmpSys->Data.HostName, (char *) hostnameParam, sizeof(tmpSys->Data.HostName) - 1))
    {
      retVal = tmpSys;
      break;
    }

    // Break if current hostname matches the wildcard leading
    // host in the list
    if (tmpSys != NULL &&
        tmpSys->Data.HostNameWithWildcard[0] == '*' &&
        StrStrIA((char *)hostnameParam, (char *)(tmpSys->Data.HostNameWithWildcard + 1)) != NULL)
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
    if (listPos->Data.Type == RESP_A)
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): Type:A\t%s/%s -> %s", listPos->Data.HostName, listPos->Data.HostNameWithWildcard, listPos->Data.SpoofedIp);
    }
    else if (listPos->Data.Type == RESP_CNAME)
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): Type:CNAME\t%s/%s -> %s/%s", listPos->Data.HostName, listPos->Data.HostNameWithWildcard, listPos->Data.CnameHost, listPos->Data.SpoofedIp);
    }
    else
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): INVALID\t%s/%s -> %s", listPos->Data.HostName, listPos->Data.HostNameWithWildcard, listPos->Data.SpoofedIp);
    }
  }
}




void FillInWildcardHostname(PHOSTNODE tmpNode)
{
  char tmpBuf[1024];
  ZeroMemory(tmpBuf, sizeof(tmpBuf));

  // If HostName starts with the WildCard character * 
  // 1. Copy the HostName to the HostNameWithWildcard field
  // 2. Remove the leading wildcard character from HostName

  CopyMemory(tmpNode->Data.HostNameWithWildcard, tmpNode->Data.HostName, strnlen(tmpNode->Data.HostName, sizeof(tmpNode->Data.HostName) - 1));
  strncpy(tmpBuf, &tmpNode->Data.HostName[1], sizeof(tmpBuf) - 1);
  strncpy(tmpNode->Data.HostName, tmpBuf, sizeof(tmpNode->Data.HostName) - 1);
}
