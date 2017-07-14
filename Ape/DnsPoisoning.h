#pragma once

#include <Windows.h>
#include "APE.h" 

void ParseDnsPoisoningConfigFile(char *pConfigFile);
int DetermineSpoofingResponseData(PSCANPARAMS pParams);
DWORD WINAPI DnsResponseSniffer(LPVOID lpParam);

void *DnsResponsePoisonerGetHost2Spoof(u_char *pData);
int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam);