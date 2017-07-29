#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <Shlwapi.h>
#include <stdarg.h>
#include <sys/timeb.h>
#include <icmpapi.h>

#include "APESniffer.h"
#include "LinkedListSystems.h"
#include "LinkedListConnections.h"
#include "Logging.h"
#include "NetworkFunctions.h"



void Mac2String(unsigned char macAddr[BIN_MAC_LEN], unsigned char *outputBuffer, int outputBufferSize)
{
  if (outputBuffer && outputBufferSize > 0 && macAddr != NULL && outputBufferSize >= MAX_MAC_LEN)
  {
    snprintf((char *)outputBuffer, outputBufferSize - 1, "%02X-%02X-%02X-%02X-%02X-%02X", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
  }
}



int GetAliasByIfcIndex(int ifcIndex, char *aliasNameBuffer, int bufferLength)
{
  int retVal = NOK;
  MIB_IF_ROW2 ifcRow;

  if (aliasNameBuffer == NULL || bufferLength <= 0)
  {
    goto END;
  }

  SecureZeroMemory((PVOID)&ifcRow, sizeof(MIB_IF_ROW2));
  ifcRow.InterfaceIndex = ifcIndex;

  if (GetIfEntry2(&ifcRow) == NO_ERROR)
  {
    snprintf(aliasNameBuffer, bufferLength - 1, "%ws", ifcRow.Alias);  
  }

END:

  return retVal;
}
