#pragma once

#include <Windows.h>
#include "DnsStructs.h"

BOOL DnsRequestSpoofing(unsigned char * in_pPacket, pcap_t* device_descriptor, char *pSpoofedIP, char *pSourceIP, char *pDestIP, char *pHostName);
void FixNetworkLayerData4Request(unsigned char * data, PRAW_DNS_DATA responseData);
void *DnsRequestPoisonerGetHost2Spoof(u_char *pData);
