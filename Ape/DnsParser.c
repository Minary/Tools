#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#include "APE.h"
#include "NetDNS.h"
#include "PacketProxy.h"


/*
 *
 *
 */
int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam)
{
  int retVal = OK;
  PETHDR etherHdrPtr = NULL;
  PIPHDR ipHdrPtr = NULL;     // ip header
  PUDPHDR udpHdrPtr = NULL;   // udp header
  PDNS_HDR dnsHdrPtr = NULL;  // dns header
  char *data = NULL; 
  int ipHdrLength = 0;
  int dataLength = 0;
  int index1;
  int count2;

  etherHdrPtr = (PETHDR) packetParam;
  ipHdrPtr = (PIPHDR) ((unsigned char*) packetParam + sizeof(ETHDR));
  ipHdrLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
  udpHdrPtr = (PUDPHDR) ((unsigned char*) ipHdrPtr + ipHdrLength);
  dnsHdrPtr = (PDNS_HDR) ((unsigned char*) udpHdrPtr + sizeof(UDPHDR));
  data = (char *) ((unsigned char*) dnsHdrPtr + sizeof(DNS_HDR));


  // Extract host name
  if ((dataLength = packetLengthParam - (sizeof(ETHDR) + ipHdrLength + sizeof(UDPHDR) + sizeof(PDNS_HDR))) > 0)
  {
    count2 = 0;

    for (index1 = 1; index1 < dataLength && count2 < hostBufferLengthParam; index1++)
    {
      if (data[index1] > 31 && data[index1] < 127)
      {
        hostnameParam[count2++] = data[index1];
      }
      else if (data[index1] == '\0')
      {
        break;
      }
      else
      {
        hostnameParam[count2++] = '.';
      }
    }
  }

  if (count2 > 2)
  {
    retVal = OK;
  }

  return retVal;
}
