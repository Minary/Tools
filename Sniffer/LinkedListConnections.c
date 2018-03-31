#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#include "Sniffer.h"
#include "SniffAndEvaluate.h"
#include "LinkedListConnections.h"


extern CRITICAL_SECTION gCSConnectionsList;


PCONNODE InitConnectionList()
{
  PCONNODE firstSysNode = NULL;

  EnterCriticalSection(&gCSConnectionsList);

  if ((firstSysNode = (PCONNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONNODE))) != NULL)
  {
    firstSysNode->first = 1;
    firstSysNode->next = NULL;
    firstSysNode->prev = NULL;
  }

  LeaveCriticalSection(&gCSConnectionsList);

  return firstSysNode;
}



/*
 *
 *
 */
void AddConnectionToList(PPCONNODE conNodesParam, char *srcMacStr, char *srcIpStrParam, unsigned short srcPortParam, char *dstIpStrParam, unsigned short dstPortParam)
{
  char id[MAX_ID_LEN + 1];
  PCONNODE tempNode = NULL;

  if (conNodesParam == NULL ||
     *conNodesParam == NULL ||
     srcMacStr == NULL ||
     srcIpStrParam == NULL ||
     srcPortParam <= 0 ||
     dstIpStrParam == NULL ||
     dstPortParam <= 0)
  {
    return;
  }

  EnterCriticalSection(&gCSConnectionsList);
  if ((tempNode = (PCONNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONNODE))) != NULL)
  {
    ZeroMemory(id, sizeof(id));
    snprintf(id, sizeof(id) - 1, "%s:%d->%s:%d", srcIpStrParam, srcPortParam, dstIpStrParam, dstPortParam);

    strncpy(tempNode->ID, id, sizeof(tempNode->ID) - 1);
    tempNode->Created = time(NULL);

    tempNode->srcPort = srcPortParam;
    tempNode->dstPort = dstPortParam;
    strncpy(tempNode->srcMacStr, srcMacStr, sizeof(tempNode->srcMacStr) - 1);
    strncpy(tempNode->srcIpStr, srcIpStrParam, sizeof(tempNode->srcIpStr) - 1);
    strncpy(tempNode->dstIpStr, dstIpStrParam, sizeof(tempNode->dstIpStr) - 1);

    // Prepend new element to the list.
    tempNode->prev = NULL;
    tempNode->first = 0;
    tempNode->next = *conNodesParam;
    ((PCONNODE)*conNodesParam)->prev = tempNode;
    *conNodesParam = tempNode;
  }

  LeaveCriticalSection(&gCSConnectionsList);
}


PCONNODE ConnectionNodeExists(PCONNODE conNodesParam, char *id)
{
  PCONNODE retVal = NULL;
  PCONNODE tmpConnection;
  int counter = 0;
  
  EnterCriticalSection(&gCSConnectionsList);
  if (id != NULL && 
      (tmpConnection = conNodesParam) != NULL)
  {

    // Go to the end of the list
    for (counter = 0; counter < MAX_CONNECTION_COUNT; counter++)
    {
      if (tmpConnection != NULL)
      {
        if (!strncmp(tmpConnection->ID, id, sizeof(tmpConnection->ID)))
        {
          retVal = tmpConnection;
          break;
        }
      }

      if ((tmpConnection = tmpConnection->next) == NULL)
      {
        break;
      }
    }
  }

  LeaveCriticalSection(&gCSConnectionsList);

  return retVal;
}


void ConnectionDeleteNode(PPCONNODE conNodesParam, char *conId)
{
  int retVal = 0;
  PCONNODE tempNode, q;
  char tmpBuffer[MAX_BUF_SIZE + 1];

  if (conNodesParam != NULL && *conNodesParam != NULL && conId != NULL)
  {
    ZeroMemory(tmpBuffer, sizeof(tmpBuffer));
    EnterCriticalSection(&gCSConnectionsList);

    // Remove first node.
    if (!strncmp(((PCONNODE)*conNodesParam)->ID, conId, MAX_ID_LEN) && ((PCONNODE)*conNodesParam)->first == 0)
    {
      tempNode = *conNodesParam;
      *conNodesParam = ((PCONNODE)*conNodesParam)->next;
      ((PCONNODE)*conNodesParam)->prev = NULL;

      if (tempNode->data != NULL)
      {
        WriteHttpDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
        HeapFree(GetProcessHeap(), 0, tempNode->data);
      }

      HeapFree(GetProcessHeap(), 0, tempNode);
      goto END;
    }

    q = (PCONNODE)*conNodesParam;
    while (q->next != NULL && q->next->next != NULL && q->first == 0)
    {
      if (!strncmp(q->ID, conId, MAX_ID_LEN))
      {
        tempNode = q->next;
        q->next = tempNode->next;
        tempNode->next->prev = q;

        if (tempNode->data != NULL && tempNode->dataLength)
        {
          WriteHttpDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
          HeapFree(GetProcessHeap(), 0, tempNode->data);
        }

        HeapFree(GetProcessHeap(), 0, tempNode);
        goto END;
      }
      q = q->next;
    }
  }

END:

  LeaveCriticalSection(&gCSConnectionsList);

  return;
}


void ConnectionAddData(PCONNODE nodeParam, char *dataParam, int dataLengthParam)
{
  if (nodeParam == NULL || dataParam == NULL || dataLengthParam <= 0)
  {
    return;
  }

  EnterCriticalSection(&gCSConnectionsList);

  // The first data chunk. Allocate memory and save
  // the copy there.
  if (nodeParam->data == NULL)
  {
    if ((nodeParam->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataLengthParam + 3)) != NULL)
    {
      memset(nodeParam->data, '.', dataLengthParam + 2);
      CopyMemory(nodeParam->data, dataParam, dataLengthParam);
      //printf("DATA0 |%s|\n", pNode->Data);
      nodeParam->dataLength = dataLengthParam + 2;
    }


  /*
   * Append the new data block to the existing
   * data.
   *
   */
  }
  else
  {
    if ((nodeParam->data = (unsigned char *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nodeParam->data, nodeParam->dataLength + dataLengthParam + 3)) != NULL)
    {
      if (dataLengthParam > 4 && (!strncmp(dataParam, "GET ", 3) || !strncmp(dataParam, "POST ", 4)))
      {
        WriteHttpDataToPipe((char *)nodeParam->data, nodeParam->dataLength, nodeParam->srcMacStr, nodeParam->srcIpStr, nodeParam->srcPort, nodeParam->dstIpStr, nodeParam->dstPort);

        if (HeapFree(GetProcessHeap(), 0, nodeParam->data))
        {
          nodeParam->dataLength = 0;
          if ((nodeParam->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataLengthParam + 3)) != NULL)
          {
            memset(nodeParam->data, '.', dataLengthParam + 2);
            CopyMemory(nodeParam->data, dataParam, dataLengthParam);
            nodeParam->dataLength = dataLengthParam + 2;
          }
        }
      }
      else
      {
        memset(&nodeParam->data[nodeParam->dataLength - 1], '.', dataLengthParam + 2);
        CopyMemory(&nodeParam->data[nodeParam->dataLength - 1], dataParam, dataLengthParam);
        nodeParam->dataLength += (dataLengthParam + 2);
      }
    }
  }

  LeaveCriticalSection(&gCSConnectionsList);
}


int ConnectionCountNodes(PCONNODE conNodesParam)
{
  int retVal = 0;

  EnterCriticalSection(&gCSConnectionsList);
  while (conNodesParam != NULL)
  {
    conNodesParam = conNodesParam->next;
    retVal++;
  }

  LeaveCriticalSection(&gCSConnectionsList);

  return retVal;
}


/*
 * Remove all entries that contain more than MAX_CONNECTION_VOLUME bytes
 * or are oldern than TCP_MAX_ACTIVITY.
 *
 */
void RemoveOldConnections(PPCONNODE conNodesParam)
{
  PCONNODE tempNode, q;
  time_t now = time(NULL);

  EnterCriticalSection(&gCSConnectionsList);

  if (conNodesParam != NULL && 
      *conNodesParam != NULL && ((PCONNODE)*conNodesParam)->first == 0)
  {
    // The first entry in the linked list.
    if (now - ((PCONNODE)*conNodesParam)->Created > TCP_MAX_ACTIVITY ||
        ((PCONNODE)*conNodesParam)->dataLength > MAX_CONNECTION_VOLUME)
    {
      tempNode = *conNodesParam;
      *conNodesParam = ((PCONNODE)*conNodesParam)->next;
      ((PCONNODE)*conNodesParam)->prev = NULL;

      if (tempNode->data != NULL)
      {
        WriteHttpDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
        HeapFree(GetProcessHeap(), 0, tempNode->data);
      }

      HeapFree(GetProcessHeap(), 0, tempNode);
      goto END;
    }

    q = (PCONNODE)*conNodesParam;
    while (q->next != NULL && 
           q->next->next != NULL && 
           q->first == 0)
    {
      if (now - q->Created > TCP_MAX_ACTIVITY ||
          q->dataLength > MAX_CONNECTION_VOLUME)
      {
        tempNode = q->next;
        q->next = tempNode->next;
        tempNode->next->prev = q;

        if (tempNode->data != NULL)
        {
          WriteHttpDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
          HeapFree(GetProcessHeap(), 0, tempNode->data);
        }

        HeapFree(GetProcessHeap(), 0, tempNode);
        goto END;
      }

      q = q->next;
    }
  }

END:

  LeaveCriticalSection(&gCSConnectionsList);
}



void WriteHttpDataToPipe(char *dataParam, int dataLengthParam, char *srcMacStrParam, char *srcIpStrParam, unsigned short srcPortParam, char *dstIpStrParam, unsigned short dstPortParam)
{
  unsigned char *dataPipe = NULL;
  int bufLen = 0;

  // Write data to pipe
  if ((dataPipe = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataLengthParam + 200)) != NULL)
  {
    snprintf((char *)dataPipe, dataLengthParam + 80, "HTTPREQ||%s||%s||%d||%s||%d||%s", srcMacStrParam, srcIpStrParam, srcPortParam, dstIpStrParam, dstPortParam, dataParam);
    strcat((char *)dataPipe, "\r\n");
    bufLen = strlen((char *)dataPipe);

    WriteOutput((char *)dataPipe, bufLen);
    HeapFree(GetProcessHeap(), 0, dataPipe);
  }
}