#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>

#include "DnsStructs.h"
#include "Logging.h"
#include "ModeGenericSniffer.h"
#include "NetworkFunctions.h"
#include "Sniffer.h"
#include "SniffAndEvaluate.h"


int ModeGenericSnifferStart(PSCANPARAMS scanParamsParam)
{
  int retVal = 0;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  char adapter[MAX_BUF_SIZE + 1];
  char bpfFilter[MAX_BUF_SIZE + 1];
  int counter = 0;
  int interfaceNum = 0;
  struct bpf_program filterCode;
  unsigned int netMask = 0;

  // Open device list.
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, tempBuffer) == -1)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Error in pcap_findalldevs_ex() : %s", tempBuffer);
    retVal = 2;
    goto END;
  }

  ZeroMemory(adapter, sizeof(adapter));
  for (counter = 0, device = allDevices; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, (char *)scanParamsParam->IfcName)) //pIFCName))
    {
      strcpy(adapter, device->name);
      break;
    }
  }

  // Open interface.
  if ((scanParamsParam->IfcReadHandle = pcap_open(adapter, 65536, PCAP_OPENFLAG_PROMISCUOUS, PCAP_READTIMEOUT, NULL, tempBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Unable to open the adapter \"%s\"", scanParamsParam->IfcName);
    retVal = 3;
    goto END;
  }

  // Compiling + setting the filter
  if (device->addresses != NULL)
  {
    netMask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
  }
  else
  {
    netMask = 0xffffff;
  }

  ZeroMemory(&filterCode, sizeof(filterCode));
  ZeroMemory(bpfFilter, sizeof(bpfFilter));

  if (scanParamsParam->PcapPattern != NULL)
  {
    snprintf(bpfFilter, sizeof(bpfFilter) - 1, "%s", scanParamsParam->PcapPattern);
  }

  if (pcap_compile((pcap_t *)scanParamsParam->IfcReadHandle, &filterCode, bpfFilter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Unable to compile the packet filter");
    retVal = 4;
    goto END;
  }

  if (pcap_setfilter((pcap_t *)scanParamsParam->IfcReadHandle, &filterCode) < 0)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Error setting the filter.");
    retVal = 5;
    goto END;
  }

  // We dont need this list anymore.
  pcap_freealldevs(allDevices);

  LogMsg(DBG_INFO, "GeneralSniffer() : General scanner started. Waiting for \"%s\" data on device \"%s\"", bpfFilter, adapter);
  // Start intercepting data packets.
  pcap_loop((pcap_t *)scanParamsParam->IfcReadHandle, 0, (pcap_handler)GenericSnifferCallback, (unsigned char *)scanParamsParam);
  LogMsg(DBG_INFO, "GeneralSniffer() : General scanner stopped");

END:

  // Release all allocated resources.
  if (allDevices)
  {
    pcap_freealldevs(allDevices);
  }

  return retVal;
}


void GenericSnifferCallback(u_char *callbackParam, const struct pcap_pkthdr *headerParam, const u_char *packetDataParam)
{
  PETHDR etherHdr = (PETHDR)packetDataParam;
  char srcMacStr[64];
  char dstMacStr[64];
  char srcIpStr[64];
  char dstIpStr[64];
  char proto[MAX_BUF_SIZE + 1];
  PETHDR ethrHdrPtr = (PETHDR)packetDataParam;
  PARPHDR arpDataPtr = NULL;
  PIPHDR ipHdrPtr = NULL;
  PTCPHDR tcpHdrPtr = NULL;
  PUDPHDR udpHdrPtr = NULL;
  int ipLength = 0;
  int totalLength = 0;
  int ipHdrLength = 0;
  int tcpHdrLength = 0;
  int tcpDataLength = 0;
  unsigned char data[1500 + 1];
  unsigned char realData[1500 + 1];
  unsigned char *readlDataPtr = NULL;
  unsigned char tempBuffer[MAX_BUF_SIZE + 1];
  int counter = 0;

  if (htons(ethrHdrPtr->ether_type) == 0x0800)
  {
    ZeroMemory(dstMacStr, sizeof(dstMacStr));
    ZeroMemory(srcMacStr, sizeof(srcMacStr));
    ZeroMemory(srcIpStr, sizeof(srcIpStr));
    ZeroMemory(dstIpStr, sizeof(dstIpStr));
    ZeroMemory(proto, sizeof(proto));

    Mac2String(etherHdr->ether_shost, (unsigned char *)srcMacStr, sizeof(srcMacStr) - 1);
    Mac2String(etherHdr->ether_dhost, (unsigned char *)dstMacStr, sizeof(dstMacStr) - 1);

    // IPv4
    if (htons(etherHdr->ether_type) == 0x0800)
    {
      ipHdrPtr = (PIPHDR)(packetDataParam + 14);

      ipLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
      totalLength = ntohs(ipHdrPtr->tlen);

      snprintf(dstIpStr, sizeof(dstIpStr) - 1, "%d.%d.%d.%d", ipHdrPtr->daddr.byte1, ipHdrPtr->daddr.byte2, ipHdrPtr->daddr.byte3, ipHdrPtr->daddr.byte4);
      snprintf(srcIpStr, sizeof(srcIpStr) - 1, "%d.%d.%d.%d", ipHdrPtr->saddr.byte1, ipHdrPtr->saddr.byte2, ipHdrPtr->saddr.byte3, ipHdrPtr->saddr.byte4);

      if (ipHdrPtr->proto == 1)
      {
printf("ICMP\t%s  %s\n\n", srcIpStr, dstIpStr);

      // TCP data packet
      }
      else if (ipHdrPtr->proto == IP_PROTO_TCP)
      {
        tcpHdrPtr = (PTCPHDR)((u_char*)ipHdrPtr + ipLength);
        totalLength = ntohs(ipHdrPtr->tlen);

        tcpHdrLength = tcpHdrPtr->doff * 4;
        tcpDataLength = totalLength - ipHdrLength - tcpHdrLength;

//printf("TCP\t%s:%d  %s:%d ", srcIpStr, ntohs(tcpHdrPtr->sport), dstIpStr, ntohs(tcpHdrPtr->dport));
        if (tcpDataLength > 0)
        {
          strncpy((char *)data, (char *)tcpHdrPtr + tcpHdrLength, tcpDataLength);
          ZeroMemory(realData, sizeof(realData));
          Stringify(data, tcpDataLength, realData);

          for (counter = 0, readlDataPtr = realData; counter < tcpDataLength; counter += 64)
          {
            ZeroMemory(tempBuffer, sizeof(tempBuffer));
            memcpy((char *)tempBuffer, (char *)readlDataPtr + counter, 64);
////printf("\n\t%s", tempBuffer);
          }

          ZeroMemory(tempBuffer, sizeof(tempBuffer));
          memcpy((char *)tempBuffer, (char *)readlDataPtr + counter, 64);
////printf("\n\t%s|", tempBuffer);
        }
//printf("\n");
      }
      else if (ipHdrPtr->proto == IP_PROTO_UDP)
      {
        udpHdrPtr = (PUDPHDR)((u_char*)ipHdrPtr + ipLength);


printf("UDP\t%s:%d  %s:%d\n", srcIpStr, ntohs(udpHdrPtr->sport), dstIpStr, ntohs(udpHdrPtr->dport));
if (ntohs(udpHdrPtr->sport) == 53)
{
  char hostResBuffer[1024];
  char *hostRes[20];
  ZeroMemory(hostRes, sizeof(hostRes));
  ZeroMemory(hostResBuffer, sizeof(hostResBuffer));

  GetHostResolution(udpHdrPtr, hostRes);

  for (int i = 0; i < 20 && hostRes[i] != NULL; i++)
  {
    strncat(hostResBuffer, hostRes[i], sizeof(hostResBuffer)-1);
    strcat(hostResBuffer, ",");
    HeapFree(GetProcessHeap(), 0, hostRes[i]);
  }

  //int idx = strnlen(hostResBuffer, sizeof(hostResBuffer) - 1) - 1;
  //int idx = strlen(hostResBuffer) - 1;
  //hostResBuffer[idx] = NULL;
  printf("REC: %s\n", hostResBuffer);
}
printf("\n");


      }
    }

  // IPv6
  }
  else if (htons(ethrHdrPtr->ether_type) == 0x0806)
  {
    /*
    ZeroMemory(lDstMAC, sizeof(lDstMAC));
    ZeroMemory(lSrcMAC, sizeof(lSrcMAC));
    ZeroMemory(lDstIP, sizeof(lDstIP));
    ZeroMemory(lSrcIP, sizeof(lSrcIP));
    lARPData = (PARPHDR) (pkt_data + 14);

    MAC2string(lARPData->sha, (unsigned char *) lSrcMAC, sizeof(lSrcMAC) - 1);
    MAC2string(lARPData->tha, (unsigned char *) lDstMAC, sizeof(lDstMAC) - 1);

    snprintf(lSrcIP, sizeof(lSrcIP) - 1, "%d.%d.%d.%d", lARPData->spa[0], lARPData->spa[1], lARPData->spa[2], lARPData->spa[3]);
    snprintf(lDstIP, sizeof(lDstIP) - 1, "%d.%d.%d.%d", lARPData->tpa[0], lARPData->tpa[1], lARPData->tpa[2], lARPData->tpa[3]);

    printf("\nSRC %s/%s -> DST %s/%s - Type [%s]", lSrcMAC, lSrcIP, lDstMAC, lDstIP, (ntohs(lARPData->opcode) == ARP_REQUEST)? "ARP Request" : "ARP Reply");
    */
  }
}


/*
void GetHostResolution(unsigned char* udpHdrPtr, char *hostRes[])
{
  PDNS_HEADER dnsHdr = (PDNS_HEADER)((unsigned char*)udpHdrPtr + sizeof(UDPHDR));
  char *hostname = (char *)((unsigned char*)dnsHdr + sizeof(DNS_HEADER));
  //char **hostRes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(char[20]));
  int hostResIndex = 0;


  // Packet is a DNS RESPONSE
  // and packet contains response data
  if (dnsHdr->qr == 1 &&
      ntohs(dnsHdr->ans_count) > 0)
  {
    int stop = 0;
    RES_RECORD answers[20];
    char *buf = dnsHdr;
    char host[1024];

    ZeroMemory(answers, sizeof(answers));
    ZeroMemory(host, sizeof(host));

    hostRes[hostResIndex] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 128);
    ChangeToDnsNameFormat(dnsHdr + 1, host, sizeof(host));
    CopyMemory(hostRes[hostResIndex], host, strnlen(host, sizeof(host) - 1));
    hostResIndex++;

    // move ahead of the dns header and the query field
    // Add 2 because of the leading and trailing (0) length definition
    unsigned char *reader = ((char *)dnsHdr) + sizeof(DNS_HEADER) + (strlen((const char*)host) + 2) + sizeof(QUESTION);
    
    for (int i = 0; i < ntohs(dnsHdr->ans_count) && i < 20; i++)
    {
      answers[i].name = ReadName(reader, buf, &stop);
      reader = reader + stop;
      answers[i].resource = (PR_DATA)(reader);
      reader = reader + sizeof(R_DATA);

      // If its an ipv4 address
      if (ntohs(answers[i].resource->type) == 1)
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

        for (int j = 0; j < ntohs(answers[i].resource->data_len); j++)
        {
          answers[i].rdata[j] = reader[j];
        }

        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
        reader = reader + ntohs(answers[i].resource->data_len);

        char temp[32];
        ZeroMemory(temp, sizeof(temp));
        IpBin2String(answers[i].rdata, temp, sizeof(temp));

        // Create and populate hostname data buffer
        hostRes[hostResIndex] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 33);
        CopyMemory(hostRes[hostResIndex], temp, strnlen(temp, sizeof(temp)-1));
        hostResIndex++;     

      // IPv6
      }
      else if (ntohs(answers[i].resource->type) == 28)
      {
        answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

        for (int j = 0; j < ntohs(answers[i].resource->data_len); j++)
        {
          answers[i].rdata[j] = reader[j];
        }

        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
        reader = reader + ntohs(answers[i].resource->data_len);

        char temp[128];
        ZeroMemory(temp, sizeof(temp));
        Ipv6Bin2String(answers[i].rdata, temp, sizeof(temp));

        // Create and populate hostname data buffer
        hostRes[hostResIndex] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 129);
        CopyMemory(hostRes[hostResIndex], temp, strnlen(temp, sizeof(temp) - 1));
        hostResIndex++;
      }
      else
      {
        answers[i].rdata = ReadName(reader, buf, &stop);
        reader = reader + stop;
      }
    }
  }

  return hostRes;
}


u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
  unsigned char *name;
  unsigned int p = 0, jumped = 0, offset;
  int i, j;

  *count = 1;
  name = (unsigned char*)malloc(256);

  name[0] = '\0';

  //read the names in 3www6google3com format
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
      *count = *count + 1; //if we havent jumped to another location then we can count up
    }
  }

  name[p] = '\0'; //string complete
  if (jumped == 1)
  {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }

  //now convert 3www6google3com0 to www.google.com
  for (i = 0; i<(int)strlen((const char*)name); i++)
  {
    p = name[i];
    for (j = 0; j<(int)p; j++)
    {
      name[i] = name[i + 1];
      i = i + 1;
    }
    name[i] = '.';
  }
  name[i - 1] = '\0'; //remove the last dot
  return name;
}


void ChangeToDnsNameFormat(unsigned char* input, unsigned char* output, int outputlen)
{
  int len = -1;
  int i = 0;

  if (input == NULL)
    return;

  ZeroMemory(output, outputlen);

  while (input[i] != 0 && 
         i < outputlen)
  {
    len = input[i];
    i++;

    strncat(output, &input[i], len);
    strcat(output, ".");
    i += len;
  }

  output[i-1] = 0;
}

*/