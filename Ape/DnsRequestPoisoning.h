#pragma once

#include <Windows.h>

void *DnsRequestPoisonerGetHost2Spoof(u_char *pData);
unsigned char* dns2Text2(unsigned char* reader, unsigned char* buffer, int *count);
void InjectDnsPacket(unsigned char * in_pPacket, pcap_t* device_descriptor, char *pSpoofedIP, char *pSourceIP, char *pDestIP, char *pHostName);
