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
  unsigned char SpoofedIp[MAX_IP_LEN + 1];
  unsigned char CnameHost[MAX_BUF_SIZE + 1];
  DNS_RESPONSE_TYPE Type;
} HOSTDATA;


typedef struct 
{
  HOSTDATA Data;
  BOOL isTail;
  struct HOSTNODE *prev;
  struct HOSTNODE *next;
} HOSTNODE, *PHOSTNODE, **PPHOSTNODE;


PHOSTNODE InitHostsList();
void AddSpoofedIpToList(PPHOSTNODE listHead, unsigned char *pHostName, unsigned char *pSpoofedIP);
void AddSpoofedCnameToList(PPHOSTNODE listHead, unsigned char *hostNameParam, unsigned char *cnameHost, unsigned char *spoofedIpParam);
PHOSTNODE GetNodeByHostname(PHOSTNODE sysNodesParam, unsigned char *hostnameParam);
void PrintDnsSpoofingRulesNodes(PHOSTNODE listHead);
