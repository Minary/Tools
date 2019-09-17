#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "DnsPoisoning.h"
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


void AddSpoofedIpToList(PPHOSTNODE listHead, unsigned char* mustMatchParam, unsigned char *hostNameParam, unsigned long ttlParam, unsigned char *spoofedIpParam)
{
  PHOSTNODE tmpNode = NULL;

  if ((tmpNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) == NULL)
  {
    return;
  }

  char* mustMatchStr = "y";
  tmpNode->Data.DoesMatch = TRUE;
  if (strcmp(mustMatchParam, "n") == 0 || 
      strcmp(mustMatchParam, "N") == 0)
  {
    tmpNode->Data.DoesMatch = FALSE;
    mustMatchStr = "n";
  }

  char* isPatternStr = "n";
  tmpNode->Data.IsWildcard = FALSE;
  if (strstr(hostNameParam, '*') != NULL)
  {
    tmpNode->Data.IsWildcard = TRUE;
    isPatternStr = "y";
  }

  CopyMemory(tmpNode->Data.HostName, hostNameParam, sizeof(tmpNode->Data.HostName) - 1);
  tmpNode->Data.TTL = ttlParam;
  CopyMemory(tmpNode->Data.SpoofedIp, spoofedIpParam, sizeof(tmpNode->Data.SpoofedIp) - 1);
  
  if (tmpNode->Data.HostName[0] == '*')
  {
    FillInWildcardHostname(tmpNode);
  }

  tmpNode->Data.Type = RESP_A;
  tmpNode->prev = NULL;
  tmpNode->isTail = FALSE;

  // Insert new record at the beginning of the list
  tmpNode->next = *listHead;
  ((PHOSTNODE)*listHead)->prev = tmpNode;
  *listHead = tmpNode;

  LogMsg(DBG_INFO, "AddSpoofedIpToList(): Spoofed DNS/A record added: %s/%s, mustMatch:%s/%s, isPattern:%s", hostNameParam, spoofedIpParam, mustMatchParam, mustMatchStr, isPatternStr);
}


void AddSpoofedCnameToList(PPHOSTNODE listHead, unsigned char *mustMatchParam, unsigned char *hostNameParam, long ttlParam, unsigned char *cnameHostParam, unsigned char *spoofedIpParam)
{
  PHOSTNODE tmpNode = NULL;

  if ((tmpNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) == NULL)
  {
    return;
  }
  
  char* mustMatchStr = "y";
  tmpNode->Data.DoesMatch = TRUE;
  if (strcmp(mustMatchParam, "n") == 0 ||
    strcmp(mustMatchParam, "N") == 0)
  {
    tmpNode->Data.DoesMatch = FALSE;
    mustMatchStr = "n";
  }

  char* isPatternStr = "n";
  tmpNode->Data.IsWildcard = FALSE;
  if (strchr(hostNameParam, '*') != NULL)
  {
    tmpNode->Data.IsWildcard = TRUE;
    isPatternStr = "y";
  }

  CopyMemory(tmpNode->Data.HostName, hostNameParam, sizeof(tmpNode->Data.HostName) - 1);
  tmpNode->Data.TTL = ttlParam;
  CopyMemory(tmpNode->Data.CnameHost, cnameHostParam, sizeof(tmpNode->Data.CnameHost) - 1);
  CopyMemory(tmpNode->Data.SpoofedIp, spoofedIpParam, sizeof(tmpNode->Data.SpoofedIp) - 1);
  CopyMemory(tmpNode->Data.CnameHost, cnameHostParam, sizeof(tmpNode->Data.CnameHost) - 1);

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
  LogMsg(DBG_INFO, "AddSpoofedIpToList(): Spoofed DNS/CNAME record added: %s/%s/%s, mustMatch:%s/%s, isPattern:%s", hostNameParam, cnameHostParam, spoofedIpParam, mustMatchParam, mustMatchStr, isPatternStr);
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
    if (tmpSys == NULL)
    {
      continue;
    }

    // Break if 
    // - record is NO pattern
    // - hostname in the list equals the requested hostname
    // - hostnames MUST match
    if (tmpSys->Data.IsWildcard == FALSE &&
        strncmp((char *)tmpSys->Data.HostName, (char *)hostnameParam, sizeof(tmpSys->Data.HostName) == 0) &&
        tmpSys->Data.DoesMatch == TRUE)
    {
      printf("WHOOP(0): hostnameParam:%s\n", hostnameParam);
      retVal = tmpSys;
      break;
    }

    // Break if 
    // - record IS pattern
    // - current hostname equals the pattern (with wildcards: * ?)
    // - hostname pattern MUST match
    if (tmpSys->Data.IsWildcard == TRUE && 
        WildcardCompare(tmpSys->Data.HostNameWithWildcard, (char*)hostnameParam)  == TRUE &&
        tmpSys->Data.DoesMatch == TRUE)
    {
      printf("WHOOP(1): hostnameParam:%s\n", hostnameParam);
      retVal = tmpSys;
      break;
    }

    // Break if 
    // - record is NO pattern
    // - hostname in the list equals the requested hostname
    // - hostnames MUST NOT match
    if (tmpSys->Data.IsWildcard == FALSE &&
        strncmp((char*)tmpSys->Data.HostName, (char*)hostnameParam, sizeof(tmpSys->Data.HostName) - 1) != 0 &&
        tmpSys->Data.DoesMatch == FALSE)
    {
      printf("WHOOP(2): hostnameParam:%s\n", hostnameParam);
      retVal = tmpSys;
      break;
    }

    // Break if 
    // - record IS pattern
    // - current hostname equals the pattern (with wildcards: * ?)
    // - hostname pattern MUST NOT match
    if (tmpSys->Data.IsWildcard == TRUE &&
        WildcardCompare(tmpSys->Data.HostNameWithWildcard, (char*)hostnameParam) == FALSE &&
        tmpSys->Data.DoesMatch == FALSE)
    {
      printf("WHOOP(3): hostnameParam:%s\n", hostnameParam);
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
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): Type:A\t%s/%s -> %s, ttl=%lu, must match:%s", listPos->Data.HostName, listPos->Data.HostNameWithWildcard, listPos->Data.SpoofedIp, listPos->Data.TTL, listPos->Data.DoesMatch?"y":"n");
    }
    else if (listPos->Data.Type == RESP_CNAME)
    {
      LogMsg(DBG_DEBUG, "PrintDnsSpoofingRulesNodes(): Type:CNAME\t%s/%s -> %s/%s, ttl=%lu, must match:%s", listPos->Data.HostName, listPos->Data.HostNameWithWildcard, listPos->Data.CnameHost, listPos->Data.SpoofedIp, listPos->Data.TTL, listPos->Data.DoesMatch ? "y" : "n");
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
  tmpNode->Data.IsWildcard = TRUE;
}


BOOL WildcardCompare(const char* pattern, const char* string)
{
  if (*pattern == '\0' && *string == '\0')		// Check if string is at end or not.
    return TRUE;

  if (*pattern == '?' || *pattern == *string)		//Check for single character missing or match
    return WildcardCompare(pattern + 1, string + 1);

  if (*pattern == '*')
    return WildcardCompare(pattern + 1, string) || WildcardCompare(pattern, string + 1);		// Check for multiple character missing

  return FALSE;
}