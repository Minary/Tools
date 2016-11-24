#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Shlwapi.h>

#include "APE.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "DNSResponsePoisoning.h"
#include "NetDns.h"

extern PHOSTNODE gHostsList;


/*
 *
 *
 */
void *DnsResponsePoisonerGetHost2Spoof(u_char *dataParam)
{
  PETHDR ethrHdr = (PETHDR)dataParam;
  PIPHDR ipHdr = NULL;
  PUDPHDR udpHdr = NULL;
  int ipHdrLen = 0;
  char *data = NULL;
  char *dnsData = NULL;
  PHOSTNODE retVal = NULL;
  PHOSTNODE tmpNode = NULL;
  PDNS_HDR dnsHdr = NULL;
  unsigned char *reader = NULL;
  int stop;
  unsigned char *peerName = NULL;


  if (ethrHdr == NULL || htons(ethrHdr->ether_type) != ETHERTYPE_IP)
  {
    return retVal;
  }

  ipHdr = (PIPHDR)(dataParam + 14);

  if (ipHdr == NULL || ipHdr->proto != IP_PROTO_UDP)
  {
    return retVal;
  }

  ipHdrLen = (ipHdr->ver_ihl & 0xf) * 4;

  if (ipHdrLen <= 0)
  {
    return retVal;
  }

  udpHdr = (PUDPHDR)((unsigned char*)ipHdr + ipHdrLen);

  if (udpHdr == NULL || udpHdr->ulen <= 0 || ntohs(udpHdr->sport) != UDP_DNS)
  {
    return retVal;
  }

  dnsData = ((char*)udpHdr + sizeof(UDPHDR));
  dnsHdr = (PDNS_HDR)&dnsData[sizeof(DNS_HDR)];

  if (dnsHdr == NULL)
  {
    return retVal;
  }

  if (ntohs(dnsHdr->q_count) <= 0)
  {
    return retVal;
  }

  reader = (unsigned char *)&dnsData[sizeof(DNS_HDR)];
  stop = 0;
  peerName = dns2Text(reader, (unsigned char *)dnsHdr, &stop);

  if ((tmpNode = GetNodeByHostname(gHostsList, peerName)) != NULL)
  {
    retVal = tmpNode;
  }

  return retVal;
}


/*
 * From dns2Text
 *
 */
unsigned char* dns2Text(unsigned char* reader, unsigned char* buffer, int *count)
{
  unsigned char *name;
  unsigned int p = 0;
  unsigned int jumped = 0;
  unsigned int offset;
  int i;
  int j;

  *count = 1;
  name = (unsigned char*)malloc(256);
  name[0] = '\0';

  // Read the names in 3www6google3com format
  while (*reader != 0)
  {
    if (*reader >= 192)
    {
      offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }
    else
    {
      name[p++] = *reader;
    }

    reader = reader + 1;

    if (jumped == 0)
    {
      *count += 1; //if we havent jumped to another location then we can count up    
    }
  }

  name[p] = '\0'; //string complete

  if (jumped == 1)
  {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }


  //now convert 3www6google3com0 to www.google.com
  for (i = 0; i < (int)strlen((const char*)name); i++)
  {
    p = name[i];
    for (j = 0; j < (int)p; j++)
    {
      name[i] = name[i + 1];
      i++;
    }

    name[i] = '.';
  }

  name[i - 1] = '\0'; //remove the last dot

  return name;
}


