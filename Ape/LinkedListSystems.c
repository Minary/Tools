#include <stdio.h>
#include <string.h>
#include <time.h>

#include "APE.h"
#include "LinkedListSystems.h"


extern CRITICAL_SECTION csSystemsLL; 


/*
 *
 *
 */
int GetListCopy(PSYSNODE nodesParam, PSYSTEMNODE sysArrayParam)
{
  int counter = 0;
  char srcMac[MAX_BUF_SIZE + 1];


  EnterCriticalSection(&csSystemsLL);

  while(nodesParam != NULL)
  {
    ZeroMemory(srcMac, sizeof(srcMac));
    snprintf(srcMac, sizeof(srcMac) - 1, "%02x:%02x:%02x:%02x:%02x:%02x", nodesParam->data.sysMacBin[0], nodesParam->data.sysMacBin[1], nodesParam->data.sysMacBin[2], nodesParam->data.sysMacBin[3], nodesParam->data.sysMacBin[4], nodesParam->data.sysMacBin[5]);

    if (strnlen((char *) nodesParam->data.sysIpStr, MAX_IP_LEN) > 0)
    {
      CopyMemory(sysArrayParam[counter].sysIpStr, nodesParam->data.sysIpStr, MAX_IP_LEN);
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

  if ((firstSysNode = (PSYSNODE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSNODE))) != NULL)
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
  PSYSNODE tmpNode = NULL;
  char tmpBuf[MAX_BUF_SIZE + 1];
  char lSMAC[MAX_BUF_SIZE + 1];
  struct tm *newTime;
  time_t clock;

  EnterCriticalSection(&csSystemsLL);

  if (sysNodesParam != NULL && *sysNodesParam != NULL && sysMacParam != NULL && sysIpParam != NULL)
  {
    ZeroMemory(tmpBuf, sizeof(tmpBuf));
    time(&clock);
    newTime = localtime(&clock); 
    snprintf(tmpBuf, sizeof(tmpBuf) - 1, "%s", asctime(newTime));

    while (tmpBuf[strlen(tmpBuf)-1] == '\r' || tmpBuf[strlen(tmpBuf)-1] == '\n')
      tmpBuf[strlen(tmpBuf)-1] = '\0';


    ZeroMemory(lSMAC, sizeof(lSMAC));
    snprintf(lSMAC, sizeof(lSMAC) - 1, "%02x:%02x:%02x:%02x:%02x:%02x", sysMacParam[0], sysMacParam[1], sysMacParam[2], sysMacParam[3], sysMacParam[4], sysMacParam[5]);

    // Entry already exists. Update IP and timestamp.
    //    if ((lTmpNode = GetNodeByMAC(*pSysNodes, pSysMAC)) != NULL)
    if ((tmpNode = GetNodeByIp(*sysNodesParam, sysIpBinParam)) != NULL)
    {
      CopyMemory(tmpNode->data.TimeStamp, tmpBuf, sizeof(tmpBuf));
      CopyMemory(tmpNode->data.sysIpStr, sysIpParam, MAX_IP_LEN);
      CopyMemory(tmpNode->data.sysIpBin, sysIpBinParam, BIN_IP_LEN);

    // Entry doesn't exist. Create it.
    }
    else if ((tmpNode = (PSYSNODE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSNODE))) != NULL)
    {
      printf("AddToSystemsList():  New system found  %s/%s\n", lSMAC, sysIpParam);

      CopyMemory(tmpNode->data.sysIpStr, sysIpParam, MAX_IP_LEN);
      CopyMemory(tmpNode->data.sysMacBin, sysMacParam, BIN_MAC_LEN);
      CopyMemory(tmpNode->data.sysIpBin, sysIpBinParam, BIN_IP_LEN);
      CopyMemory(tmpNode->data.TimeStamp, tmpBuf, sizeof(tmpBuf));

      tmpNode->prev = NULL;
      tmpNode->first = 0;
      tmpNode->next = *sysNodesParam;
      ((PSYSNODE) *sysNodesParam)->prev = tmpNode;
      *sysNodesParam = tmpNode;
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
  PSYSNODE tmpSys;
  int count = 0;

  EnterCriticalSection(&csSystemsLL);

  if ((tmpSys = sysNodesParam) != NULL)
  {
    // Go to the end of the list
    for (count = 0; count < MAX_SYSTEMS_COUNT; count++)
    {
      if (tmpSys != NULL)
      {
        // System found.
        if (! memcmp(tmpSys->data.sysIpBin, ipBinParam, BIN_IP_LEN))
        {
          retVal = tmpSys;
          break;
        }
      }

      if ((tmpSys = tmpSys->next) == NULL)
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
PSYSNODE GetNodeByMAC(PSYSNODE sysNodesParam, unsigned char macParam[BIN_MAC_LEN])
{
  PSYSNODE retVal = NULL;
  PSYSNODE tmpSys;
  int count = 0;

  EnterCriticalSection(&csSystemsLL);


  if (macParam != NULL && (tmpSys = sysNodesParam) != NULL)
  {

    // Go to the end of the list
    for (count = 0; count < MAX_SYSTEMS_COUNT; count++)
    {

      if (tmpSys != NULL)
      {
        if (!memcmp(tmpSys->data.sysMacBin, macParam, BIN_MAC_LEN))
        {
          retVal = tmpSys;
          break;
        }
      }

      if ((tmpSys = tmpSys->next) == NULL)
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
void DeleteNode(char *pNodeName)
{
  /*
  PSYSNODE tmp;

  EnterCriticalSection(&gCSSystemsLL);

  // Remove first node.
  if(gSysStart->info == num)
  {
  tmp = gSysStart;
  gSysStart = gSysStart->next;  
  gSysStart->prev = NULL;
  free(tmp);
  return;
  }

  q = gSysStart;



  while(q->next->next != NULL)
  {
  if(q->next->info == num)     
  {
  tmp = q->next;
  q->next = tmp->next;
  tmp->next->prev = q;
  free(tmp);
  return;
  }
  q = q->next;
  }


  // Remove last node
  if(q->next->info == num)    
  {
  tmp = q->next;
  free(tmp);
  q->next = NULL;
  return;
  }
  */
  LeaveCriticalSection(&csSystemsLL);
}




/*
 *
 *
 */
int CountNodes(PSYSNODE sysNodesParam)
{   
  int retVal = 0;

  while(sysNodesParam != NULL)
  {
    sysNodesParam = sysNodesParam->next;
    retVal++;
  }

  return retVal;
}

