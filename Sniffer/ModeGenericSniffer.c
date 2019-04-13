#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>

#include "DnsStructs.h"
#include "Logging.h"
#include "ModeGenericSniffer.h"
#include "ModeMinary.h"
#include "NetworkFunctions.h"
#include "Sniffer.h"
#include "SniffAndEvaluate.h"


// Global variables
pcap_t *gPcapHandle;



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

  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)Sniffer_ControlHandler, TRUE);

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
  if ((gPcapHandle = pcap_open(adapter, 65536, PCAP_OPENFLAG_PROMISCUOUS, PCAP_READTIMEOUT, NULL, tempBuffer)) == NULL)
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

  if (pcap_compile(gPcapHandle, &filterCode, bpfFilter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Unable to compile the packet filter");
    retVal = 4;
    goto END;
  }

  if (pcap_setfilter(gPcapHandle, &filterCode) < 0)
  {
    LogMsg(DBG_ERROR, "GeneralSniffer() : Error setting the filter.");
    retVal = 5;
    goto END;
  }

  // We dont need this list anymore.
  pcap_freealldevs(allDevices);

  LogMsg(DBG_INFO, "GeneralSniffer() : General scanner started. Waiting for \"%s\" data on device \"%s\"", bpfFilter, adapter);
  // Start intercepting data packets.
  pcap_loop(gPcapHandle, 0, (pcap_handler)GenericSnifferCallback, (unsigned char *)scanParamsParam);
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

      // TCP data packet
      }
      else if (ipHdrPtr->proto == IP_PROTO_TCP)
      {
        tcpHdrPtr = (PTCPHDR)((u_char*)ipHdrPtr + ipLength);
        totalLength = ntohs(ipHdrPtr->tlen);

        tcpHdrLength = tcpHdrPtr->doff * 4;
        tcpDataLength = totalLength - ipHdrLength - tcpHdrLength;

        if (tcpDataLength > 0)
        {
          strncpy((char *)data, (char *)tcpHdrPtr + tcpHdrLength, tcpDataLength);
          ZeroMemory(realData, sizeof(realData));
          Stringify(data, tcpDataLength, realData);

          for (counter = 0, readlDataPtr = realData; counter < tcpDataLength; counter += 64)
          {
            ZeroMemory(tempBuffer, sizeof(tempBuffer));
            memcpy((char *)tempBuffer, (char *)readlDataPtr + counter, 64);
          }

          ZeroMemory(tempBuffer, sizeof(tempBuffer));
          memcpy((char *)tempBuffer, (char *)readlDataPtr + counter, 64);
        }
      }
      else if (ipHdrPtr->proto == IP_PROTO_UDP)
      {
        udpHdrPtr = (PUDPHDR)((u_char*)ipHdrPtr + ipLength);
      }
    }

  // IPv6
  }
  else if (htons(ethrHdrPtr->ether_type) == 0x0806)
  {

  }
}


BOOL Sniffer_ControlHandler(DWORD pControlType)
{
  switch (pControlType)
  {
    // Handle the CTRL-C signal. 
  case CTRL_C_EVENT:
    LogMsg(DBG_INFO, "Ctrl-C event : Exiting process");
    pcap_breakloop(gPcapHandle);
    LogMsg(DBG_INFO, "Ctrl-C event : pcap closed");
    return FALSE;

  case CTRL_CLOSE_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Close event : Exiting process");
    pcap_breakloop(gPcapHandle);
    LogMsg(DBG_INFO, "Ctrl-Close event : pcap closed");
    return FALSE;

  case CTRL_BREAK_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Break event : Exiting process");
    pcap_breakloop(gPcapHandle);
    LogMsg(DBG_INFO, "Ctrl-Break event : pcap closed");
    return FALSE;

  case CTRL_LOGOFF_EVENT:
    printf("Ctrl-Logoff event : Exiting process");
    pcap_breakloop(gPcapHandle);
    printf("Ctrl-Logoff event : pcap closed");
    return FALSE;

  case CTRL_SHUTDOWN_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Shutdown event : Exiting process");
    pcap_breakloop(gPcapHandle);
    LogMsg(DBG_INFO, "Ctrl-Shutdown event : pcap closed", pControlType);
    return FALSE;

  default:
    LogMsg(DBG_INFO, "Unknown event \"%d\" : Exiting process", pControlType);
    pcap_breakloop(gPcapHandle);
    LogMsg(DBG_INFO, "Unknown event \"%d\" : pcap closed", pControlType);
    return FALSE;
  }
}