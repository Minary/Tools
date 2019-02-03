#pragma once

#include "RouterIPv4.h"


int ListInterfaceDetails();
int GetInterfaceDetails(char *pIFCName, PSCANPARAMS pScanParams);
int GetInterfaceName(char *interfaceNameParam, char *realInterfaceNameParam, int bufLength);
