
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

  char SrcMAC[MAX_MAC_LEN+1];
  char SrcIP[MAX_IP_LEN+1];
  char DstIP[MAX_IP_LEN+1];
  unsigned short SrcPort;
  unsigned short DstPort;
  int DataLen;
  unsigned char *Data;

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
int CountConnectionNodes(PCONNODE pConNodes);
void ConnectionDeleteNode(PPCONNODE pConNodes, char *pID);
int ConnectionCountNodes(PCONNODE pConNodes);
void ConnectionAddData(PCONNODE pNode, char *pData, int pDataLen);
void RemoveOldConnections(PPCONNODE pConNodes);
void WriteHTTPDataToPipe(char *pData, int pDataLen, char *pSMAC, char *pSrcIP, unsigned short pSrcPort, char *pDstIP, unsigned short pDstPort);


#endif