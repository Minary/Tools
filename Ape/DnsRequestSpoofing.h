#pragma once

#include <Windows.h>

void DnsRequestSpoofing(unsigned char * in_pPacket, pcap_t* device_descriptor, char *pSpoofedIP, char *pSourceIP, char *pDestIP, char *pHostName);
