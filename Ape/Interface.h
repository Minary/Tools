#include <Windows.h>

#ifndef __INTERFACE_H__
#define __INTERFACE_H__

int ListInterfaceDetails();
int GetInterfaceDetails(char *pIFCName, PSCANPARAMS pScanParams);
int GetInterfaceName(char *interfaceNameParam, char *realInterfaceNameParam, int bufLength);

#endif 