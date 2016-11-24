#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


#include "APE.h"
#include "LinkedListHttpInjections.h"
#include "SLRE.h"



/*
 *
 *
 */
PHTTPINJECTIONNODE InitHttpInjectionList()
{
  PHTTPINJECTIONNODE firsHostNode = NULL;

  if ((firsHostNode = (PHTTPINJECTIONNODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HTTPINJECTIONNODE))) != NULL)
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
void AddItemToList(PPHTTPINJECTIONNODE httpInjectionNodesParam, unsigned char *requestedHostParam, unsigned char *requestedUrlParam, unsigned char *redirectedUrlParam)
{
  PHTTPINJECTIONNODE tmpNode = NULL;

  if ((tmpNode = (PHTTPINJECTIONNODE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HTTPINJECTIONNODE))) != NULL)
  {
    //printf("AddHostToList(1) :  /%s/%s/\n", pHostName, pSpoofedIP);
    CopyMemory(tmpNode->sData.RequestedHost, requestedHostParam, sizeof(tmpNode->sData.RequestedHost)-1);
    CopyMemory(tmpNode->sData.RequestedURL, requestedUrlParam, sizeof(tmpNode->sData.RequestedURL)-1);
    CopyMemory(tmpNode->sData.RedirectedURL, redirectedUrlParam, sizeof(tmpNode->sData.RedirectedURL)-1);
    //LogMsg(DBG_INFO, "AddSpoofedIPToList() : Add spoofed system to list : %s/%s", pHostName, pSpoofedIP);
    tmpNode->prev = NULL;
    tmpNode->first = 0;
    tmpNode->next = *httpInjectionNodesParam;
    ((PHTTPINJECTIONNODE) *httpInjectionNodesParam)->prev = tmpNode;
    *httpInjectionNodesParam = tmpNode;
  }
}



/*
 *
 *
 */
PHTTPINJECTIONNODE GetNodeByRequestedUrl(PHTTPINJECTIONNODE httpInjectionNodesParam, unsigned char *requestedHostParam, unsigned char *requestedUrlParam)
{
  PHTTPINJECTIONNODE retVal = NULL;
  PHTTPINJECTIONNODE tmpSys;
  int count = 0;

  if ((tmpSys = httpInjectionNodesParam) == NULL)
  {
    return retVal;
  }

  for (count = 0; count < MAX_NODE_COUNT5; count++)
  {
    if (tmpSys != NULL)
    {
//      if (! _strnicmp((char *)lTmpSys->sData.RequestedHost, (char *) pRequestedHost,  sizeof(lTmpSys->sData.RequestedHost)-1) &&
//          ! _strnicmp((char *)lTmpSys->sData.RequestedURL, (char *) pRequestedURL,  sizeof(lTmpSys->sData.RequestedURL)-1))
      if (slre_match((char *) tmpSys->sData.RequestedHost, (char *) requestedHostParam, strlen((char *) requestedHostParam), NULL, 0, SLRE_IGNORE_CASE) &&
          slre_match((char *) tmpSys->sData.RequestedURL, (char *) requestedUrlParam, strlen((char *) requestedUrlParam), NULL, 0, SLRE_IGNORE_CASE) > 0)
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

  return retVal;
}




/*
 *
 *
 */
void EnumHttpInjectionNodes(PHTTPINJECTIONNODE sysNodesParam)
{
  char temp[MAX_BUF_SIZE + 1];

  if (sysNodesParam == NULL)
  {
    return;
  }

  while (sysNodesParam != NULL)
  {
    _snprintf(temp, sizeof(temp) - 1, "%s %s -> %s", sysNodesParam->sData.RequestedHost, sysNodesParam->sData.RequestedURL, sysNodesParam->sData.RedirectedURL);
    printf("%s\n", temp);
    sysNodesParam = sysNodesParam->next;
  }
}