#pragma once

#include <Windows.h>
#include "LinkedListSpoofedDnsHosts.h"


BOOL DnsResponseSpoofing(unsigned char * rawPacket, pcap_t *deviceHandle, PPOISONING_DATA spoofingRecord, char *srcIp, char *dstIp);
void FixNetworkLayerData4Response(unsigned char * data, PRAW_DNS_DATA responseData);
PPOISONING_DATA *DnsResponsePoisonerGetHost2Spoof(u_char *dataParam);
