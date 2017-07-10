#include "NetworkPackets.h"

void GenerateUdpPacket(unsigned char * packet, unsigned short udpPacketLength, unsigned short srcPort, unsigned short dstPort)
{
  PUDPHDR udpHdr = (PUDPHDR)packet;

  //fill up fields in UDP header
  udpHdr->sport = htons(srcPort);	// source port of attack_packet
  udpHdr->dport = htons(dstPort);	// destination port of attack_packet
  udpPacketLength = udpPacketLength - sizeof(IPHDR) - sizeof(ETHDR);
  udpHdr->ulen = htons(udpPacketLength);		// length
  udpHdr->sum = 0;
}


unsigned short in_cksum(unsigned short * addr, int length)
{
  register int sum = 0;
  unsigned short checkSum = 0;
  register unsigned short *w = addr;
  register int numLeft = length;

  // using a 32 bit accumulator (sum), u16_add sequential 16 bit words to it, 
  // and at the end, fold back all the carry bits from the top 16 bits into
  // the lower 16 bits.
  while (numLeft > 1)
  {
    sum += *w++;
    numLeft -= 2;
  }

  //handle odd byte
  if (numLeft == 1)
  {
    *(unsigned char *)(&checkSum) = *(unsigned char *)w;
    sum += checkSum;
  }

  // u16_add back carry outs from top 16 bits to low 16 bits 
  sum = (sum >> 16) + (sum & 0xffff);    // u16_add high 16 to low 16 
  sum += (sum >> 16);                     // u16_add carry 
  checkSum = ~sum;                        // truncate to 16 bits

  return checkSum;
}
