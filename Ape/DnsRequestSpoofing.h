#pragma once

#include <Windows.h>
#include "DnsStructs.h"
#include "LinkedListSpoofedDNSHosts.h"

BOOL DnsRequestSpoofing(unsigned char * rawPacket, pcap_t *deviceHandle, PHOSTNODE spoofingRecord, char *srcIp, char *dstIp);
void FixNetworkLayerData4Request(unsigned char * data, PRAW_DNS_DATA responseData);
PPOISONING_DATA DnsRequestPoisonerGetHost2Spoof(u_char *pData);
