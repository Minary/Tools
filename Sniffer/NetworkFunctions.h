#ifndef __NETWORKFUNCTIONS__
#define __NETWORKFUNCTIONS__

#include <Windows.h>
#include <iphlpapi.h>

#include "Sniffer.h"


void IpBin2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen);
void Ipv6Bin2String(unsigned char ipAddrParam[BIN_IPv6_LEN], unsigned char *outputParam, int outputLengthParam);
void Mac2String(unsigned char macAddr[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);
int GetAliasByIfcIndex(int ifcIndex, char *aliasNameBuffer, int bufferLength);

#endif
