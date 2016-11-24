#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#include "ApeSniffer.h"
#include "NetDns.h"
#include "PacketProxy.h"


/*
*
*
*/
int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostNameParam, int hostBufferLengthParam)
{
  int retVal = OK;
  PETHDR etherPacketPtr = NULL;
  PIPHDR ipHdrPtr = NULL;     // ip header
  PUDPHDR udpHdrPtr = NULL;   // udp header
  PDNS_HDR dnsHdrPtr = NULL;  // dns header
  char *data = NULL;    // we modify data so keep orig              
  int ipHdrLength = 0;
  int dataLength = 0;
  int index1;
  int index2;
  int lHdrLen = 0;

  etherPacketPtr = (PETHDR)packetParam;
  ipHdrPtr = (PIPHDR)((unsigned char*)packetParam + sizeof(ETHDR));
  ipHdrLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
  udpHdrPtr = (PUDPHDR)((unsigned char*)ipHdrPtr + ipHdrLength);
  dnsHdrPtr = (PDNS_HDR)((unsigned char*)udpHdrPtr + sizeof(UDPHDR));
  data = (char *)((unsigned char*)dnsHdrPtr + sizeof(DNS_HDR));

  // Extract host name
  if ((dataLength = packetLengthParam - (sizeof(ETHDR) + ipHdrLength + sizeof(UDPHDR) + sizeof(PDNS_HDR))) > 0)
  {
    index2 = 0;

    for (index1 = 1; index1 < dataLength && index2 < hostBufferLengthParam; index1++)
    {
      if (data[index1] > 31 && data[index1] < 127)
      {
        hostNameParam[index2++] = data[index1];
      }
      else if (data[index1] == '\0')
      {
        break;
      }
      else
      {
        hostNameParam[index2++] = '.';
      }
    }
  }

  if (index2 > 2)
  {
    retVal = OK;
  }

  return retVal;
}
