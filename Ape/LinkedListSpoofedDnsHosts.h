#pragma once

#include "APE.h"

#define MAX_NODE_COUNT 1024 


typedef enum
{
  RESP_A,
  RESP_CNAME
} DNS_RESPONSE_TYPE;


typedef struct 
{
  unsigned char HostName[MAX_BUF_SIZE + 1];
  unsigned char HostNameWithWildcard[MAX_BUF_SIZE + 1];
  unsigned char SpoofedIp[MAX_IP_LEN + 1];
  unsigned char CnameHost[MAX_BUF_SIZE + 1];
  unsigned long TTL;
  DNS_RESPONSE_TYPE Type;
} HOSTDATA;


typedef struct 
{
  HOSTDATA Data;
  BOOL isTail;
  struct HOSTNODE *prev;
  struct HOSTNODE *next;
} HOSTNODE, *PHOSTNODE, **PPHOSTNODE;


typedef struct
{
  char HostnameToSpoof[256];
  PHOSTNODE HostnodeToSpoof;
} POISONING_DATA, *PPOISONING_DATA;


PHOSTNODE InitHostsList();
void AddSpoofedIpToList(PPHOSTNODE listHead, unsigned char *pHostName, long ttlParam, unsigned char *pSpoofedIP);
void AddSpoofedCnameToList(PPHOSTNODE listHead, unsigned char *hostNameParam, long ttlParam, unsigned char *cnameHost, unsigned char *spoofedIpParam);
PHOSTNODE GetNodeByHostname(PHOSTNODE sysNodesParam, unsigned char *hostnameParam);
void PrintDnsSpoofingRulesNodes(PHOSTNODE listHead);
void FillInWildcardHostname(PHOSTNODE tmpNode);