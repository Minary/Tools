
#ifndef __LINKEDLISTCONNECTIONS__
#define __LINKEDLISTCONNECTIONS__

/*
 * Type declarations.
 *
 */
typedef struct CONNODE
{
  int first;

  char ID[MAX_ID_LEN + 1];
  time_t Created;

  char srcMacStr[MAX_MAC_LEN + 1];
  char srcIpStr[MAX_IP_LEN + 1];
  char dstIpStr[MAX_IP_LEN + 1];
  unsigned short srcPort;
  unsigned short dstPort;
  int dataLength;
  unsigned char *data;

  struct CONNODE *prev;
  struct CONNODE *next;
} CONNODE, *PCONNODE, **PPCONNODE;



/*
 * Function forward declarations.
 *
 */
PCONNODE InitConnectionList();
void AddConnectionToList(PPCONNODE pConNodes, char *pSrcMAC, char *pSrcIP, unsigned short pSrcPort, char *pDstIP, unsigned short pDstPort);
PCONNODE ConnectionNodeExists(PCONNODE pConNodes, char *pID);
void ConnectionDeleteNode(PPCONNODE pConNodes, char *pID);
int ConnectionCountNodes(PCONNODE pConNodes);
void ConnectionAddData(PCONNODE pNode, char *pData, int pDataLen);
void RemoveOldConnections(PPCONNODE pConNodes);
void WriteHTTPDataToPipe(char *pData, int pDataLen, char *pSMAC, char *pSrcIP, unsigned short pSrcPort, char *pDstIP, unsigned short pDstPort);

#endif
