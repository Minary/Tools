#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ApeSniffer.h"
#include "LinkedListSystems.h"


extern CRITICAL_SECTION csSystemsLL;


/*
*
*
*/
int GetListCopy(PSYSNODE nodesParam, PSYSTEMNODE sysArrayParam)
{
  int counter = 0;
  char srcMacStr[MAX_BUF_SIZE + 1];


  EnterCriticalSection(&csSystemsLL);

  while (nodesParam != NULL)
  {
    ZeroMemory(srcMacStr, sizeof(srcMacStr));
    snprintf(srcMacStr, sizeof(srcMacStr) - 1, "%02x:%02x:%02x:%02x:%02x:%02x", nodesParam->data.sysMacBin[0], nodesParam->data.sysMacBin[1], nodesParam->data.sysMacBin[2], nodesParam->data.sysMacBin[3], nodesParam->data.sysMacBin[4], nodesParam->data.sysMacBin[5]);

    if (strnlen((char *)nodesParam->data.sysIpBin, MAX_IP_LEN) > 0)
    {
      CopyMemory(sysArrayParam[counter].sysIpStr, nodesParam->data.sysIpBin, MAX_IP_LEN);
      CopyMemory(sysArrayParam[counter].sysMacBin, nodesParam->data.sysMacBin, BIN_MAC_LEN);
      CopyMemory(sysArrayParam[counter].sysIpBin, nodesParam->data.sysIpBin, BIN_IP_LEN);
      counter++;
    }

    nodesParam = nodesParam->next;
  }

  LeaveCriticalSection(&csSystemsLL);

  return counter;
}


/*
*
*
*/
PSYSNODE InitSystemList()
{
  PSYSNODE firstSysNode = NULL;

  EnterCriticalSection(&csSystemsLL);

  if ((firstSysNode = (PSYSNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSNODE))) != NULL)
  {
    firstSysNode->first = 1;
    firstSysNode->next = NULL;
    firstSysNode->prev = NULL;
  }

  LeaveCriticalSection(&csSystemsLL);

  return firstSysNode;
}


/*
*
*
*/
void AddToSystemsList(PPSYSNODE sysNodesParam, unsigned char sysMacParam[BIN_MAC_LEN], char *sysIpParam, unsigned char sysIpBinParam[BIN_IP_LEN])
{
  PSYSNODE tempNode = NULL;
  char tempBuffer[MAX_BUF_SIZE + 1];
  char srcMacStr[MAX_BUF_SIZE + 1];
  struct tm *newTime;
  time_t aClock;

  EnterCriticalSection(&csSystemsLL);

  if (sysNodesParam != NULL && *sysNodesParam != NULL && sysMacParam != NULL && sysIpParam != NULL)
  {
    ZeroMemory(tempBuffer, sizeof(tempBuffer));
    time(&aClock);
    newTime = localtime(&aClock);
    snprintf(tempBuffer, sizeof(tempBuffer) - 1, "%s", asctime(newTime));

    while (tempBuffer[strlen(tempBuffer) - 1] == '\r' || tempBuffer[strlen(tempBuffer) - 1] == '\n')
    {
      tempBuffer[strlen(tempBuffer) - 1] = '\0';
    }

    ZeroMemory(srcMacStr, sizeof(srcMacStr));
    snprintf(srcMacStr, sizeof(srcMacStr) - 1, "%02x:%02x:%02x:%02x:%02x:%02x", sysMacParam[0], sysMacParam[1], sysMacParam[2], sysMacParam[3], sysMacParam[4], sysMacParam[5]);

    // Entry already exists. Update IP and timestamp.
    //    if ((lTmpNode = GetNodeByMAC(*pSysNodes, pSysMAC)) != NULL)
    if ((tempNode = GetNodeByIp(*sysNodesParam, sysIpBinParam)) != NULL)
    {
      CopyMemory(tempNode->data.timeStamp, tempBuffer, sizeof(tempBuffer));
      CopyMemory(tempNode->data.sysIpStr, sysIpParam, MAX_IP_LEN);
      CopyMemory(tempNode->data.sysIpBin, sysIpBinParam, BIN_IP_LEN);

      // Entry doesn't exist. Create it.
    }
    else if ((tempNode = (PSYSNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSNODE))) != NULL)
    {
      printf("AddToSystemsList() :  New system found  %s/%s\n", srcMacStr, sysIpParam);

      CopyMemory(tempNode->data.sysIpStr, sysIpParam, MAX_IP_LEN);
      CopyMemory(tempNode->data.sysMacBin, sysMacParam, BIN_MAC_LEN);
      CopyMemory(tempNode->data.sysIpBin, sysIpBinParam, BIN_IP_LEN);
      CopyMemory(tempNode->data.timeStamp, tempBuffer, sizeof(tempBuffer));

      tempNode->prev = NULL;
      tempNode->first = 0;
      tempNode->next = *sysNodesParam;
      ((PSYSNODE)*sysNodesParam)->prev = tempNode;
      *sysNodesParam = tempNode;
    }
  }

  LeaveCriticalSection(&csSystemsLL);
}



/*
*
*
*/
PSYSNODE GetNodeByIp(PSYSNODE sysNodesParam, unsigned char ipBinParam[BIN_IP_LEN])
{
  PSYSNODE retVal = NULL;
  PSYSNODE tempSys;
  int counter = 0;

  EnterCriticalSection(&csSystemsLL);

  if ((tempSys = sysNodesParam) != NULL)
  {
    // Go to the end of the list
    for (counter = 0; counter < MAX_SYSTEMS_COUNT; counter++)
    {
      if (tempSys != NULL)
      {
        // System found.
        if (!memcmp(tempSys->data.sysIpBin, ipBinParam, BIN_IP_LEN))
        {
          retVal = tempSys;
          break;
        }
      }

      if ((tempSys = tempSys->next) == NULL)
      {
        break;
      }
    }
  }

  LeaveCriticalSection(&csSystemsLL);

  return retVal;
}





/*
*
*
*/
PSYSNODE GetNodeByMac(PSYSNODE sysNodesParam, unsigned char pMAC[BIN_MAC_LEN])
{
  PSYSNODE retVal = NULL;
  PSYSNODE tempSys;
  int counter = 0;

  EnterCriticalSection(&csSystemsLL);


  if (pMAC != NULL && (tempSys = sysNodesParam) != NULL)
  {

    // Go to the end of the list
    for (counter = 0; counter < MAX_SYSTEMS_COUNT; counter++)
    {

      if (tempSys != NULL)
      {
        if (!memcmp(tempSys->data.sysMacBin, pMAC, BIN_MAC_LEN))
        {
          retVal = tempSys;
          break;
        }
      }

      if ((tempSys = tempSys->next) == NULL)
      {
        break;
      }
    }
  }


  LeaveCriticalSection(&csSystemsLL);

  return retVal;
}






/*
*
*
*/
int CountNodes(PSYSNODE sysNodesParam)
{
  int retVal = 0;

  while (sysNodesParam != NULL)
  {
    sysNodesParam = sysNodesParam->next;
    retVal++;
  }

  return retVal;
}

