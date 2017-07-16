#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>

#include "ApeSniffer.h"
#include "GenericSniffer.h"
#include "NetDns.h"
#include "SniffAndEvaluate.h"
#include "NetworkFunctions.h"



/*
*
*
*/
int GenericSniffer(PSCANPARAMS scanParamsParam)
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
    if (StrStrI(device->name, (char *)scanParamsParam->IFCName)) //pIFCName))
    {
      strcpy(adapter, device->name);
      break;
    }
  }

  // Open interface.
  if ((scanParamsParam->IfcReadHandle = pcap_open(adapter, 65536, PCAP_OPENFLAG_PROMISCUOUS, PCAP_READTIMEOUT, NULL, tempBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Unable to open the adapter \"%s\"", scanParamsParam->IFCName);
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




/*
*
*
*/
void GenericSnifferCallback(u_char *callbackParam, const struct pcap_pkthdr *headerParam, const u_char *packetDataParam)
{
  PETHDR lEHdr = (PETHDR)packetDataParam;
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

    Mac2String(lEHdr->ether_shost, (unsigned char *)srcMacStr, sizeof(srcMacStr) - 1);
    Mac2String(lEHdr->ether_dhost, (unsigned char *)dstMacStr, sizeof(dstMacStr) - 1);
    printf("\n\n");

    // IPv4
    if (htons(lEHdr->ether_type) == 0x0800)
    {
      ipHdrPtr = (PIPHDR)(packetDataParam + 14);

      ipLength = (ipHdrPtr->ver_ihl & 0xf) * 4;
      totalLength = ntohs(ipHdrPtr->tlen);

      snprintf(dstIpStr, sizeof(dstIpStr) - 1, "%d.%d.%d.%d", ipHdrPtr->daddr.byte1, ipHdrPtr->daddr.byte2, ipHdrPtr->daddr.byte3, ipHdrPtr->daddr.byte4);
      snprintf(srcIpStr, sizeof(srcIpStr) - 1, "%d.%d.%d.%d", ipHdrPtr->saddr.byte1, ipHdrPtr->saddr.byte2, ipHdrPtr->saddr.byte3, ipHdrPtr->saddr.byte4);

      if (ipHdrPtr->proto == 1)
      {
        printf("ICMP\t%s  %s", srcIpStr, dstIpStr);

        // TCP data packet
      }
      else if (ipHdrPtr->proto == IP_PROTO_TCP)
      {
        tcpHdrPtr = (PTCPHDR)((u_char*)ipHdrPtr + ipLength);
        totalLength = ntohs(ipHdrPtr->tlen);

        tcpHdrLength = tcpHdrPtr->doff * 4;
        tcpDataLength = totalLength - ipHdrLength - tcpHdrLength;

        printf("TCP\t%s:%d  %s:%d ", srcIpStr, ntohs(tcpHdrPtr->sport), dstIpStr, ntohs(tcpHdrPtr->dport));


        if (tcpDataLength > 0)
        {
          strncpy((char *)data, (char *)tcpHdrPtr + tcpHdrLength, tcpDataLength);
          ZeroMemory(realData, sizeof(realData));
          stringify(data, tcpDataLength, realData);


          for (counter = 0, readlDataPtr = realData; counter < tcpDataLength; counter += 64)
          {
            ZeroMemory(tempBuffer, sizeof(tempBuffer));
            memcpy((char *)tempBuffer, (char *)readlDataPtr + counter, 64);
            printf("\n\t%s", tempBuffer);
          }

          ZeroMemory(tempBuffer, sizeof(tempBuffer));
          memcpy((char *)tempBuffer, (char *)readlDataPtr + counter, 64);
          printf("\n\t%s", tempBuffer);
        }
      }
      else if (ipHdrPtr->proto == IP_PROTO_UDP)
      {
        udpHdrPtr = (PUDPHDR)((u_char*)ipHdrPtr + ipLength);
        printf("UDP\t%s:%d  %s:%d", srcIpStr, ntohs(udpHdrPtr->sport), dstIpStr, ntohs(udpHdrPtr->dport));
      }
    }
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