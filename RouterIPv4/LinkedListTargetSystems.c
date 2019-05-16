#include <stdio.h>
#include <string.h>
#include <time.h>

#include "RouterIPv4.h"
#include "LinkedListTargetSystems.h"
#include "Logging.h"

// External global variables
extern CRITICAL_SECTION csSystemsLL;


int GetListCopy(PSYSNODE nodesParam, PSYSTEMNODE sysArrayParam)
{
  int counter = 0;
  char srcMac[MAX_BUF_SIZE + 1];

  EnterCriticalSection(&csSystemsLL);
  while (nodesParam != NULL)
  {
    ZeroMemory(srcMac, sizeof(srcMac));
    snprintf(srcMac, sizeof(srcMac) - 1, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", nodesParam->data.sysMacBin[0], nodesParam->data.sysMacBin[1], nodesParam->data.sysMacBin[2], nodesParam->data.sysMacBin[3], nodesParam->data.sysMacBin[4], nodesParam->data.sysMacBin[5]);

    if (strnlen((char *)nodesParam->data.sysIpStr, MAX_IP_LEN) > 0)
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


PSYSNODE InitSystemList()
{
  PSYSNODE listHead = NULL;

  EnterCriticalSection(&csSystemsLL);
  if ((listHead = (PSYSNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSNODE))) != NULL)
  {
    listHead->isTail = TRUE;
    listHead->next = NULL;
    listHead->prev = NULL;
  }

  LeaveCriticalSection(&csSystemsLL);

  return listHead;
}


void ClearSystemList(PPSYSNODE listHead)
{
  PSYSNODE listPos;

  EnterCriticalSection(&csSystemsLL);

  // Verify preconditions
  if (listHead == NULL ||
    *listHead == NULL ||
    ((PSYSNODE)*listHead)->isTail ||
    ((PSYSNODE)*listHead)->next == NULL)
  {
    return;
  }

  // Free all allocated resources
  PSYSNODE nextListPos = NULL; // ((PSYSNODE)*listHead)->next;
  listPos = (PSYSNODE)*listHead;
  while (listPos != NULL &&
    listPos->isTail == FALSE)
  {
    nextListPos = listPos->next;
    HeapFree(GetProcessHeap(), NULL, listPos);
    listPos = nextListPos;
  }

  // Set new list head
  *listHead = listPos;

  LeaveCriticalSection(&csSystemsLL);
}


void AddToSystemsList(PPSYSNODE listHead, unsigned char sysMacParam[BIN_MAC_LEN], char *sysIpParam, unsigned char sysIpBinParam[BIN_IP_LEN])
{
  PSYSNODE tmpNode = NULL;
  char tmpBuf[MAX_BUF_SIZE + 1];
  char srcMac[MAX_BUF_SIZE + 1];
  struct tm *newTime;
  time_t clock;

  EnterCriticalSection(&csSystemsLL);
  if (listHead == NULL || *listHead == NULL || sysMacParam == NULL || sysIpParam == NULL)
  {
    goto END;
  }

  ZeroMemory(tmpBuf, sizeof(tmpBuf));
  time(&clock);
  newTime = localtime(&clock);
  snprintf(tmpBuf, sizeof(tmpBuf) - 1, "%s", asctime(newTime));

  // Remove trailing LF/CR
  while (tmpBuf[strlen(tmpBuf) - 1] == '\r' || tmpBuf[strlen(tmpBuf) - 1] == '\n')
  {
    tmpBuf[strlen(tmpBuf) - 1] = '\0';
  }

  ZeroMemory(srcMac, sizeof(srcMac));
  snprintf(srcMac, sizeof(srcMac) - 1, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", sysMacParam[0], sysMacParam[1], sysMacParam[2], sysMacParam[3], sysMacParam[4], sysMacParam[5]);

  // Entry already exists. Update IP and timestamp.
  if ((tmpNode = GetNodeByIp(*listHead, sysIpBinParam)) != NULL)
  {
    CopyMemory(tmpNode->data.TimeStamp, tmpBuf, sizeof(tmpBuf));
    CopyMemory(tmpNode->data.sysIpStr, sysIpParam, MAX_IP_LEN);
    CopyMemory(tmpNode->data.sysIpBin, sysIpBinParam, BIN_IP_LEN);

    // Entry doesn't exist. Create it.
  }
  else if ((tmpNode = (PSYSNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSNODE))) != NULL)
  {
    LogMsg(DBG_INFO, "AddToSystemsList():  New target system added: %s/%s", srcMac, sysIpParam);

    CopyMemory(tmpNode->data.sysIpStr, sysIpParam, MAX_IP_LEN);
    CopyMemory(tmpNode->data.sysMacBin, sysMacParam, BIN_MAC_LEN);
    CopyMemory(tmpNode->data.sysIpBin, sysIpBinParam, BIN_IP_LEN);
    CopyMemory(tmpNode->data.TimeStamp, tmpBuf, sizeof(tmpBuf));

    // Set the new record at the head of the list
    tmpNode->prev = NULL;
    tmpNode->isTail = FALSE;
    tmpNode->next = *listHead;
    ((PSYSNODE)*listHead)->prev = tmpNode;
    *listHead = tmpNode;
  }

END:
  LeaveCriticalSection(&csSystemsLL);
}


PSYSNODE GetNodeByIp(PSYSNODE listHead, unsigned char ipBinParam[BIN_IP_LEN])
{
  PSYSNODE retVal = NULL;
  PSYSNODE tmpSys;
  int count = 0;

  EnterCriticalSection(&csSystemsLL);
  if ((tmpSys = listHead) == NULL)
  {
    goto END;
  }

  // Go to the end of the list
  for (count = 0; count < MAX_SYSTEMS_COUNT; count++)
  {
    if (tmpSys != NULL)
    {
      // System found.
      if (!memcmp(tmpSys->data.sysIpBin, ipBinParam, BIN_IP_LEN))
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

END:
  LeaveCriticalSection(&csSystemsLL);

  return retVal;
}


PSYSNODE GetNodeByMac(PSYSNODE listHead, unsigned char macParam[BIN_MAC_LEN])
{
  PSYSNODE retVal = NULL;
  PSYSNODE tmpSys;
  int count = 0;

  EnterCriticalSection(&csSystemsLL);
  if (macParam == NULL || (tmpSys = listHead) == NULL)
  {
    goto END;
  }

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

END:
  LeaveCriticalSection(&csSystemsLL);

  return retVal;
}


void PrintTargetSystems(PSYSNODE listHead)
{
  PSYSNODE listPos;

  for (listPos = listHead; listPos != NULL && listPos->isTail == FALSE; listPos = listPos->next)
  {
    LogMsg(DBG_DEBUG, "PrintTargetSystems(): Target system: %s / %02x-%02x-%02x-%02x-%02x-%02x", listPos->data.sysIpStr,
      listPos->data.sysMacBin[0], listPos->data.sysMacBin[1], listPos->data.sysMacBin[2],
      listPos->data.sysMacBin[3], listPos->data.sysMacBin[4], listPos->data.sysMacBin[5]);
  }
}
