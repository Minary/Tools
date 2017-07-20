#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "APE.h"
#include "LinkedListSpoofedDnsHosts.h"




/* 
 *
 *
 */
PHOSTNODE InitHostsList()
{
  PHOSTNODE firsHostNode = NULL;

  if ((firsHostNode = (PHOSTNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
  {
    firsHostNode->first = 1;
    firsHostNode->next = NULL;
    firsHostNode->prev = NULL;
  }

  return firsHostNode;
}



/*
 *
 *
 */
void AddSpoofedIpToList(PPHOSTNODE hostNodesParam, unsigned char *hostNameParam, unsigned char *spoofedIpParam)
{
  PHOSTNODE tmpNode = NULL;

  if ((tmpNode = (PHOSTNODE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
  {
    CopyMemory(tmpNode->HostData.HostName, hostNameParam, sizeof(tmpNode->HostData.HostName)-1);
    CopyMemory(tmpNode->HostData.SpoofedIP, spoofedIpParam, sizeof(tmpNode->HostData.SpoofedIP)-1);

    tmpNode->prev = NULL;
    tmpNode->first = 0;
    tmpNode->next = (struct HOSTNODE *) *hostNodesParam;
    ((PHOSTNODE) *hostNodesParam)->prev = (struct HOSTNODE *) tmpNode;
    *hostNodesParam = tmpNode;
  }
}



/*
 *
 *
 */
PHOSTNODE GetNodeByHostname(PHOSTNODE sysNodesParam, unsigned char *hostnameParam)
{
  PHOSTNODE retVal = NULL;
  PHOSTNODE tmpSys;
  int count = 0;

  if ((tmpSys = sysNodesParam) == NULL)
  {
    return retVal;
  }

  // Go to the end of the list
  for (count = 0; count < MAX_NODE_COUNT; count++)
  {
    if (tmpSys != NULL)
    {
      if (!strncmp((char *)tmpSys->HostData.HostName, (char *)hostnameParam, sizeof(tmpSys->HostData.HostName) - 1))
      {
        retVal = tmpSys;
        break;
      }
    }

    if ((tmpSys = (PHOSTNODE)tmpSys->next) == NULL)
    {
      break;
    }
  }

  return retVal;
}