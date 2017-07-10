#pragma once

#include <windows.h>

#define TYPE_A 1     // Ipv4 address
#define TYPE_NS 2    // Nameserver
#define TYPE_CNAME 5 // canonical name
#define TYPE_SOA 6   // start of authority zone
#define TYPE_PTR 12  // domain name pointer
#define TYPE_MX 15   // Mail server

#define UDP_DNS 53
#define DNS_DATA_BUF 65535



typedef struct
{	
  unsigned short a_url;   // URL in question
  unsigned short a_type;  // type of query
  unsigned short a_class; // class of query
  unsigned short a_ttl1;  // time to live
  unsigned short a_ttl2;  // time to live
  unsigned short a_len;   // length
  struct in_addr a_ip;    // IP returned
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


//typedef struct
//{	
//  unsigned short q_type;    // Type A query taken
//  unsigned short q_class;   // class
//} DNS_QUERY, *PDNS_QUERY;
  