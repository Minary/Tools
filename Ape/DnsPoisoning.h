#pragma once

#include <Windows.h>
#include "APE.h" 

void ParseDNSPoisoningConfigFile(char *pConfigFile);
int DetermineSpoofingResponseData(PSCANPARAMS pParams);
DWORD WINAPI DnsResponseSniffer(LPVOID lpParam);

void *DnsResponsePoisonerGetHost2Spoof(u_char *pData);
unsigned char* Dns2Text(unsigned char* reader, unsigned char* buffer, int *count);
int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam);