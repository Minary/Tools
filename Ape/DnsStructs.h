#pragma once

#include "DNS.h" 

typedef struct
{
  unsigned char *data;
  unsigned int dataLength;
} RAW_DNS_DATA, *PRAW_DNS_DATA;

typedef enum
{
  DNS_QUERY = 0,
  DNS_A = 1,
  DNS_CNAME = 2
} PACKET_TYPE;


typedef struct
{
  PACKET_TYPE type;
  unsigned short transactionId;
  unsigned int ttl;
  unsigned char *hostname;
  unsigned char *canonicalHost;
  unsigned char *spoofedIpAddress;
} PACKET_CUSTOMISATION, *PPACKET_CUSTOMISATION;


