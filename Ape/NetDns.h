#ifndef __NETDNS__
#define __NETDNS__

#include <windows.h>


#define T_A 1     //Ipv4 address
#define T_NS 2    //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6   // start of authority zone
#define T_PTR 12  // domain name pointer
#define T_MX 15   // Mail server

#define UDP_DNS 53
#define DNS_DATA_BUF 65535



/*
 * Type definitions
 *
 */
#pragma pack(push, 1)
typedef struct
{
  unsigned short id; // identification number
  unsigned char rd :1; // recursion desired
  unsigned char tc :1; // truncated message
  unsigned char aa :1; // authoritive answer
  unsigned char opcode :4; // purpose of message
  unsigned char qr :1; // query/response flag
  unsigned char rcode :4; // response code
  unsigned char cd :1; // checking disabled
  unsigned char ad :1; // authenticated data
  unsigned char z :1; // its z! reserved
  unsigned char ra :1; // recursion available
  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count; // number of resource entries
} DNS_HDR, *PDNS_HDR;
#pragma pack(pop)

typedef struct
{
  unsigned short qtype;
  unsigned short qclass;
} DNS_QUESTION, *PDNS_QUESTION;


#pragma pack(push, 1)
typedef struct
{
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
} R_DATA, *PR_DATA;
#pragma pack(pop)


typedef struct
{	
  unsigned short a_url;	// URL in question
  unsigned short a_type;	// type of query
  unsigned short a_class;// class of query
  unsigned short a_ttl1;	// time to live
  unsigned short a_ttl2;	// time to live
  unsigned short a_len;  // length
  struct in_addr a_ip; // IP returned
} DNS_ANSWER, *PDNS_ANSWER;


typedef struct
{
  unsigned short trans_id;	// transaction ID
  unsigned short flags;		// u16_flags
  unsigned short ques;		// no of queries
  unsigned short ans;	 	// no of answers
  unsigned short auth;		// no of authoritive
  unsigned short add;		 // no of additional
} DNS_BASIC, *PDNS_BASIC;


typedef struct
{	
  unsigned short q_type;		// Type A query taken
  unsigned short q_class;	// class
} DNS_QUERY, *PDNS_QUERY;



/*
 * Function forward declarations
 *
 */
int GetReqHostName(unsigned char *packet, int pPktLen, char *pHostName, int pHostBufLen);

#endif