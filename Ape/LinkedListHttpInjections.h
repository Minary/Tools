#pragma once

#define MAX_NODE_COUNT5 1024
#define BIN_IP_LEN5 4
#define MAX_IP_LEN5 17
#define MAX_BUF_SIZE5 1024



typedef struct HTTPINJECTIONDATA 
{
  unsigned char RequestedHost[MAX_BUF_SIZE5 + 1];
  unsigned char RequestedURL[MAX_BUF_SIZE5 + 1];
  unsigned char RedirectedURL[MAX_BUF_SIZE5 + 1];
} HTTPINJECTIONDATA;


typedef struct HTTPINJECTIONNODE 
{
  HTTPINJECTIONDATA sData;

  int first;
  struct HTTPINJECTIONNODE *prev;
  struct HTTPINJECTIONNODE *next;
} HTTPINJECTIONNODE, *PHTTPINJECTIONNODE, **PPHTTPINJECTIONNODE;



PHTTPINJECTIONNODE InitHttpInjectionList();
void AddItemToList(PPHTTPINJECTIONNODE pHTTPInjectionNodes, unsigned char *pRequestedHost, unsigned char *pRequestedURL, unsigned char *pRedirectedURL);
PHTTPINJECTIONNODE GetNodeByRequestedUrl(PHTTPINJECTIONNODE pHTTPInjectionNodes, unsigned char *pRequestedHost, unsigned char *pRequestedURL);
void EnumHttpInjectionNodes(PHTTPINJECTIONNODE pHTTPInjectionNodes);

