#pragma once

#include <Windows.h>
#include "APE.h" 

DWORD WINAPI DnsResponseSniffer(LPVOID lpParam);
int GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam);