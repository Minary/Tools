
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
void AddConnectionToList(PPCONNODE conNodes, char *srcMac, char *srcIp, unsigned short srcPort, char *dstIp, unsigned short dstPort);
PCONNODE ConnectionNodeExists(PCONNODE conNodes, char *id);
void ConnectionDeleteNode(PPCONNODE conNodes, char *id);
int ConnectionCountNodes(PCONNODE conNodes);
void ConnectionAddData(PCONNODE node, char *data, int dataLength);
void RemoveOldConnections(PPCONNODE conNodes);
void WriteHttpDataToPipe(char *data, int dataLength, char *srcMac, char *srcIp, unsigned short srcPort, char *dstIp, unsigned short dstPort);

#endif
