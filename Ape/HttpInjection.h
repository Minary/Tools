#ifndef __HTTPINJECTION__
#define __HTTPINJECTION__


//#define FORWARDHEADER "HTTP/1.1 301 Found\nLocation: http://%s\r\n\r\n"
#define FORWARDHEADER "HTTP/1.1 302 Found\nLocation: http://%s\r\n\r\n"

/*
 * Types definition
 *
 */
typedef struct
{
  char Method[16];
  char URL[1024];
  char Host[256];
} HTTPREQ, *PHTTPREQ;


/*
 * Function forward declarations
 *
 */
void ParseHTMLInjectionConfigFile(char *pConfigFile);
int InjectHttpReply(pcap_t * pIfcHandle, unsigned char *pData, int pDataLen);
int ParseRequest(char *pRequest, PHTTPREQ pHTTPReq);
unsigned short ComputeChecksum (unsigned short *pDataPtr, int pDataLen);
int SendRedirect(PETHDR pEthHdr, PIPHDR pIPHdr, PTCPHDR pTCPHdr, char *pReplacementURL, pcap_t * pIfcHandle, int pDataLen);
unsigned int GetRandomInt(unsigned int pMin, unsigned int pMax);

#endif