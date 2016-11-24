#ifndef __GENERALFUNCTIONS__
#define __GENERALFUNCTIONS__


/*
 * Function forward declarations
 *
 */
void LogMsg(int pPriority, char *pMsg, ...);
int UserIsAdmin();
void adminCheck(char *pProgName);
int GetInterfaceName(char *pIFCName, char *pRealIFCName, int pBufLen);
int GetInterfaceDetails(char *pIFCName, PSCANPARAMS pScanParams);
int GetAliasByIfcIndex(int pIfcIndex, char *pAliasBuf, int pBufLen);
int ListInterfaceDetails();
int IPAddrBelongsToLocalNet(unsigned long pLocalIP, unsigned long pNetmask, unsigned long pTestAddr);
DWORD WINAPI IPLookup(void *pParams);

#endif