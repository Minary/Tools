#define HAVE_REMOTE

#include <windows.h>
#include <stdint.h>

#include "NetBase.h"
#include "DnsStructs.h"


BOOL GetResolvedIpAddress(unsigned char *packetParam)
{
  BOOL retVal = FALSE;
  PETHDR etherHdrPtr = NULL;
  PIPHDR ipHdrPtr = NULL;       // ip header
  PUDPHDR udpHdrPtr = NULL;     // udp header                              
  PDNS_HEADER dnsHdrPtr = NULL; // dns header
  char *data = NULL;
  int ipHdrLength = 0;

  etherHdrPtr = (PETHDR)packetParam;
  ipHdrPtr = (PIPHDR)((unsigned char*)packetParam + sizeof(ETHDR));
  ipHdrLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
  udpHdrPtr = (PUDPHDR)((unsigned char*)ipHdrPtr + ipHdrLength);
  dnsHdrPtr = (PDNS_HEADER)((unsigned char*)udpHdrPtr + sizeof(UDPHDR));
  data = (char *)((unsigned char*)dnsHdrPtr + sizeof(DNS_HEADER));

  return retVal;
}


BOOL GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam)
{
  BOOL retVal = FALSE;
  PETHDR etherHdrPtr = NULL;
  PIPHDR ipHdrPtr = NULL;       // ip header
  PUDPHDR udpHdrPtr = NULL;     // udp header                              
  PDNS_HEADER dnsHdrPtr = NULL; // dns header
  char *data = NULL;
  int ipHdrLength = 0;
  int dataLength = 0;
  int index1;
  int count2;

  etherHdrPtr = (PETHDR)packetParam;
  ipHdrPtr = (PIPHDR)((unsigned char*)packetParam + sizeof(ETHDR));
  ipHdrLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
  udpHdrPtr = (PUDPHDR)((unsigned char*)ipHdrPtr + ipHdrLength);
  dnsHdrPtr = (PDNS_HEADER)((unsigned char*)udpHdrPtr + sizeof(UDPHDR));
  data = (char *)((unsigned char*)dnsHdrPtr + sizeof(DNS_HEADER));
//dnsHdrPtr->qr

  // Extract host name
  if ((dataLength = packetLengthParam - (sizeof(ETHDR) + ipHdrLength + sizeof(UDPHDR) + sizeof(PDNS_HEADER))) > 0)
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
    retVal = TRUE;
  }
  
  return retVal;
}
