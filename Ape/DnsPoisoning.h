#pragma once

#include <Windows.h>
#include "APE.h" 

DWORD WINAPI DnsResponseSniffer(LPVOID lpParam);
BOOL GetReqHostName(unsigned char *packetParam, int packetLengthParam, char *hostnameParam, int hostBufferLengthParam);