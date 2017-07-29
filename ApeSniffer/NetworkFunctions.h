#ifndef __NETWORKFUNCTIONS__
#define __NETWORKFUNCTIONS__

#include <Windows.h>
#include <iphlpapi.h>

#include "APESniffer.h"


void Mac2String(unsigned char macAddr[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);
int GetAliasByIfcIndex(int ifcIndex, char *aliasNameBuffer, int bufferLength);

#endif
