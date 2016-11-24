#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#include "APESniffer.h"
#include "SniffAndEvaluate.h"
//#include "NetworkFunctions.h"
#include "LinkedListConnections.h"


extern CRITICAL_SECTION gCSConnectionsList;


/*
*
*
*/
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

  EnterCriticalSection(&gCSConnectionsList);

  if (conNodesParam != NULL && *conNodesParam != NULL && srcMacStr != NULL && srcIpStrParam != NULL && srcPortParam > 0 && dstIpStrParam != NULL && dstPortParam > 0)
  {
    if ((tempNode = (PCONNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONNODE))) != NULL)
    {

      /*
       * Copy info to the list element
       *
       */
      ZeroMemory(id, sizeof(id));
      snprintf(id, sizeof(id) - 1, "%s:%d->%s:%d", srcIpStrParam, srcPortParam, dstIpStrParam, dstPortParam);

      strncpy(tempNode->ID, id, sizeof(tempNode->ID) - 1);
      tempNode->Created = time(NULL);

      tempNode->srcPort = srcPortParam;
      tempNode->dstPort = dstPortParam;
      strncpy(tempNode->srcMacStr, srcMacStr, sizeof(tempNode->srcMacStr) - 1);
      strncpy(tempNode->srcIpStr, srcIpStrParam, sizeof(tempNode->srcIpStr) - 1);
      strncpy(tempNode-dstIpStrParam, dstIpStrParam, sizeof(tempNode->dstIpStr) - 1);

      // Prepend new element to the list.
      tempNode->prev = NULL;
      tempNode->first = 0;
      tempNode->next = *conNodesParam;
      ((PCONNODE)*conNodesParam)->prev = tempNode;
      *conNodesParam = tempNode;
    }
  }

  LeaveCriticalSection(&gCSConnectionsList);
}




/*
*
*
*/
PCONNODE ConnectionNodeExists(PCONNODE conNodesParam, char *pID)
{
  PCONNODE retVal = NULL;
  PCONNODE lTmpCon;
  int lCount = 0;


  EnterCriticalSection(&gCSConnectionsList);

  if (pID != NULL && (lTmpCon = conNodesParam) != NULL)
  {

    // Go to the end of the list
    for (lCount = 0; lCount < MAX_CONNECTION_COUNT; lCount++)
    {
      if (lTmpCon != NULL)
      {
        if (!strncmp(lTmpCon->ID, pID, sizeof(lTmpCon->ID)))
        {
          retVal = lTmpCon;
          break;
        }
      }

      if ((lTmpCon = lTmpCon->next) == NULL)
        break;

    }
  }

  LeaveCriticalSection(&gCSConnectionsList);

  return retVal;
}



/*
*
*
*/
void ConnectionDeleteNode(PPCONNODE conNodesParam, char *pConID)
{
  int retVal = 0;
  PCONNODE tempNode, q;
  char lTemp[MAX_BUF_SIZE + 1];

  if (conNodesParam != NULL && *conNodesParam != NULL && pConID != NULL)
  {
    ZeroMemory(lTemp, sizeof(lTemp));
    EnterCriticalSection(&gCSConnectionsList);

    // Remove first node.
    if (!strncmp(((PCONNODE)*conNodesParam)->ID, pConID, MAX_ID_LEN) && ((PCONNODE)*conNodesParam)->first == 0)
    {
      tempNode = *conNodesParam;
      *conNodesParam = ((PCONNODE)*conNodesParam)->next;
      ((PCONNODE)*conNodesParam)->prev = NULL;

      if (tempNode->data != NULL)
      {
        WriteHTTPDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
        HeapFree(GetProcessHeap(), 0, tempNode->data);
      }

      HeapFree(GetProcessHeap(), 0, tempNode);
      goto END;
    }


    q = (PCONNODE)*conNodesParam;
    while (q->next != NULL && q->next->next != NULL && q->first == 0)
    {
      if (!strncmp(q->ID, pConID, MAX_ID_LEN))
      {
        tempNode = q->next;
        q->next = tempNode->next;
        tempNode->next->prev = q;

        if (tempNode->data != NULL && tempNode->dataLength)
        {
          WriteHTTPDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
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



/*
*
*
*/
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
        WriteHTTPDataToPipe((char *)nodeParam->data, nodeParam->dataLength, nodeParam->srcMacStr, nodeParam->srcIpStr, nodeParam->srcPort, nodeParam->dstIpStr, nodeParam->dstPort);
        //printf("DATA1.0.1\n");

        if (HeapFree(GetProcessHeap(), 0, nodeParam->data))
        {
          //printf("DATA1.0.2\n");
          nodeParam->dataLength = 0;
          if ((nodeParam->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataLengthParam + 3)) != NULL)
          {
            memset(nodeParam->data, '.', dataLengthParam + 2);
            CopyMemory(nodeParam->data, dataParam, dataLengthParam);
            nodeParam->dataLength = dataLengthParam + 2;
            //printf("DATA1.0.3 |%s|\n", pNode->Data);
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



/*
*
*
*/
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

  if (conNodesParam != NULL && *conNodesParam != NULL && ((PCONNODE)*conNodesParam)->first == 0)
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
        WriteHTTPDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
        HeapFree(GetProcessHeap(), 0, tempNode->data);
      }

      HeapFree(GetProcessHeap(), 0, tempNode);
      goto END;
    }
    
    q = (PCONNODE)*conNodesParam;
    while (q->next != NULL && q->next->next != NULL && q->first == 0)
    {
      if (now - q->Created > TCP_MAX_ACTIVITY || q->dataLength > MAX_CONNECTION_VOLUME)
      {
        tempNode = q->next;
        q->next = tempNode->next;
        tempNode->next->prev = q;

        if (tempNode->data != NULL)
        {
          WriteHTTPDataToPipe((char *)tempNode->data, tempNode->dataLength, tempNode->srcMacStr, tempNode->srcIpStr, tempNode->srcPort, tempNode->dstIpStr, tempNode->dstPort);
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



/*
*
*
*/
void WriteHTTPDataToPipe(char *dataParam, int dataLengthParam, char *srcMacStrParam, char *srcIpStrParam, unsigned short srcPortParam, char *dstIpStrParam, unsigned short dstPortParam)
{
  unsigned char *lDataPipe = NULL;
  int lBufLen = 0;


  // Write data to pipe
  if ((lDataPipe = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataLengthParam + 200)) != NULL)
  {
    snprintf((char *)lDataPipe, dataLengthParam + 80, "TCP||%s||%s||%d||%s||%d||%s", srcMacStrParam, srcIpStrParam, srcPortParam, dstIpStrParam, dstPortParam, dataParam);
    strcat((char *)lDataPipe, "\r\n");
    lBufLen = strlen((char *)lDataPipe);

    WriteOutput((char *)lDataPipe, lBufLen);
    HeapFree(GetProcessHeap(), 0, lDataPipe);
  }
}