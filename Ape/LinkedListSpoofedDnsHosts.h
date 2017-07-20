#pragma once

#include "APE.h"

#define MAX_NODE_COUNT 1024 


typedef struct 
{
  unsigned char HostName[MAX_BUF_SIZE + 1];
  unsigned char SpoofedIP[MAX_IP_LEN + 1];
} HOSTDATA;


typedef struct 
{
  HOSTDATA HostData;
  int first;
  struct HOSTNODE *prev;
  struct HOSTNODE *next;
} HOSTNODE, *PHOSTNODE, **PPHOSTNODE;


PHOSTNODE InitHostsList();
void AddSpoofedIpToList(PPHOSTNODE pHostNodes, unsigned char *pHostName, unsigned char *pSpoofedIP);
PHOSTNODE GetNodeByHostname(PHOSTNODE sysNodesParam, unsigned char *hostnameParam);
