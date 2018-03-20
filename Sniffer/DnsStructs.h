#pragma once

#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_SOA 6
#define TYPE_PTR 12  
#define TYPE_MX 15   

#define DNS_REQUEST 0
#define DNS_RESPONSE 1


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

//Constant sized fields of query structure
typedef struct
{
  unsigned short qtype;
  unsigned short qclass;
} QUESTION, *PQUESTION;

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
typedef struct
{
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
} R_DATA, *PR_DATA;
#pragma pack(pop)

//Pointers to resource record contents
typedef struct
{
  unsigned char *name;
  PR_DATA resource;
  unsigned char *rdata;
} RES_RECORD, *PRES_RECORD;


//Structure of a Query
typedef struct
{
  unsigned char *name;
  QUESTION *ques;
} QUERY, *PQUERY;

