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

#include "Sniffer.h"
#include "LinkedListSystems.h"
#include "LinkedListConnections.h"
#include "Logging.h"
#include "NetworkFunctions.h"


void Mac2String(unsigned char macAddr[BIN_MAC_LEN], unsigned char *outputBuffer, int outputBufferSize)
{
  if (outputBuffer && 
      outputBufferSize > 0 && 
      macAddr != NULL && 
      outputBufferSize >= MAX_MAC_LEN)
  {
    snprintf((char *)outputBuffer, outputBufferSize - 1, "%02X-%02X-%02X-%02X-%02X-%02X", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
  }
}


void IpBin2String(unsigned char ipAddrParam[BIN_IP_LEN], unsigned char *outputParam, int outputLengthParam)
{
  if (outputParam && 
      outputLengthParam > 0)
  {
    snprintf((char *)outputParam, outputLengthParam, "%d.%d.%d.%d", ipAddrParam[0], ipAddrParam[1], ipAddrParam[2], ipAddrParam[3]);
  }
}


void Ipv6Bin2String(unsigned char ipAddrParam[BIN_IPv6_LEN], unsigned char *outputParam, int outputLengthParam)
{
  if (outputParam &&
    outputLengthParam > 0)
  {
    snprintf((char *)outputParam, outputLengthParam, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
      ipAddrParam[0], ipAddrParam[1], ipAddrParam[2], ipAddrParam[3],
      ipAddrParam[4], ipAddrParam[5], ipAddrParam[6], ipAddrParam[7],
      ipAddrParam[8], ipAddrParam[9], ipAddrParam[10], ipAddrParam[11],
      ipAddrParam[12], ipAddrParam[12], ipAddrParam[14], ipAddrParam[15]
      );
  }
}


int GetAliasByIfcIndex(int ifcIndex, char *aliasNameBuffer, int bufferLength)
{
  int retVal = NOK;
  MIB_IF_ROW2 ifcRow;

  if (aliasNameBuffer == NULL || 
      bufferLength <= 0)
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
