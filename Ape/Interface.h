#pragma once

#include <Windows.h>


int ListInterfaceDetails();
int GetInterfaceDetails(char *pIFCName, PSCANPARAMS pScanParams);
int GetInterfaceName(char *interfaceNameParam, char *realInterfaceNameParam, int bufLength);
