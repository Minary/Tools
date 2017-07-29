#ifndef __NETBASE__
#define __NETBASE__

#include <Windows.h>

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800

#define IP_PROTO_UDP 17
#define IP_PROTO_TCP 6
#define IP_PROTO_ICMP 1

#define IP_HL(ip) (((ip)->u8_ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->u8_ip_vhl) >> 4)

#define UDP_DNS 53

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define BIN_MAC_LEN 6
#define MAX_MAC_LEN 18
#define BIN_IP_LEN 4
#define MAX_IP_LEN 18


/*
* Type definitions
*
*/
typedef struct
{
  unsigned char ether_dhost[BIN_MAC_LEN];  // dest Ethernet address
  unsigned char ether_shost[BIN_MAC_LEN];  // source Ethernet address
  unsigned short ether_type;     // protocol (16-bit)
} ETHDR, *PETHDR;



typedef struct
{
  unsigned char byte1;
  unsigned char byte2;
  unsigned char byte3;
  unsigned char byte4;
} IPADDRESS, *PIPADDRESS;


#pragma pack(push, 1)
typedef struct
{
  unsigned char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
  unsigned char  tos;            // Type of service 
  unsigned short tlen;           // Total length 
  unsigned short identification; // Identification
  unsigned short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
  unsigned char  ttl;            // Time to live
  unsigned char  proto;          // Protocol
  unsigned short checksum;            // Header checksum
  IPADDRESS      saddr;          // Source address
  IPADDRESS      daddr;          // Destination address
} IPHDR, *PIPHDR;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct
{
  unsigned short sport;
  unsigned short dport;
  uint32_t seq;
  uint32_t ack_seq;
  unsigned short res1 : 4,
  doff : 4,
       fin : 1,
           syn : 1,
               rst : 1,
                   psh : 1,
                       ack : 1,
                           urg : 1,
                               res2 : 2;
  unsigned short window;
  unsigned short check;
  unsigned short urg_ptr;
} TCPHDR, *PTCPHDR;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct  //1060 bytes    
{
  IPADDRESS saddr;         // 4 bytes
  IPADDRESS daddr;         // 4 bytes
  unsigned char zero;      // 1 byte
  unsigned char  proto;    // 1 byte   
  unsigned short tcp_len;  // 2 bytes     ->   12 bytes
  TCPHDR tcp;              // 20 bytes    ->   32 bytes 
  char payload[1025];      // 1025 bytes  -> 1057 bytes
} PSEUDO_TCP_HDR, *PPSEUDO_TCP_HDR;  // 1060
#pragma pack(pop)


typedef struct
{
  unsigned short sport;/*Source port */
  unsigned short dport;/*Destination port */
  unsigned short ulen;/*UDP length */
  unsigned short checksum; /*UDP checksum */
} UDPHDR, *PUDPHDR;


typedef struct icmpheader
{
  unsigned char  type;
  unsigned char  code;
  unsigned short checksum;
  unsigned short id;
  unsigned short sequence;
  unsigned	short data;
} ICMPHDR, *PICMPHDR;

typedef struct arphdr
{
  unsigned short  htype;   // format of hardware address 
  unsigned short  ptype;   // format of protocol address
  unsigned char   hlen;    // length of hardware address
  unsigned char   plen;    // length of protocol address 
  unsigned short  opcode;  // ARP/RARP operation
  unsigned char   sha[BIN_MAC_LEN];  // sender hardware address (MAC)
  unsigned char   spa[BIN_IP_LEN];   // sender protocol address (IP)
  unsigned char   tha[BIN_MAC_LEN];  // target hardware address (MAC)
  unsigned char   tpa[BIN_IP_LEN];   // target protocol address (IP)
} ARPHDR, *PARPHDR;


typedef struct pARPPacket
{
  char IFCName[1024];
  int lReqType;
  unsigned char Eth_SrcMAC[BIN_MAC_LEN];
  unsigned char Eth_DstMAC[BIN_MAC_LEN];

  unsigned char ARP_LocalMAC[BIN_MAC_LEN];
  unsigned char ARP_LocalIP[BIN_IP_LEN];
  unsigned char ARP_Dst_MAC[BIN_MAC_LEN];
  unsigned char ARP_DstIP[BIN_IP_LEN];
} ARPPacket, *PARPPacket;




//DNS header structure
typedef struct
{
  unsigned short id; // identification number
  unsigned char rd : 1; // recursion desired
  unsigned char tc : 1; // truncated message
  unsigned char aa : 1; // authoritive answer
  unsigned char opcode : 4; // purpose of message
  unsigned char qr : 1; // query/response flag

  unsigned char rcode : 4; // response code
  unsigned char cd : 1; // checking disabled
  unsigned char ad : 1; // authenticated data
  unsigned char z : 1; // its z! reserved
  unsigned char ra : 1; // recursion available

  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count; // number of resource entries
} DNS_HEADER, *PDNS_HEADER;

#endif