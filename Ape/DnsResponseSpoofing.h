#pragma once

#include <Windows.h>
#include "LinkedListSpoofedDnsHosts.h"


BOOL DnsResponseSpoofing(unsigned char * rawPacket, pcap_t *deviceHandle, char *spoofedIp, char *srcIp, char *dstIp, char *hostName);
void FixNetworkLayerData4Response(unsigned char * data, PRAW_DNS_DATA responseData);
void *DnsResponsePoisonerGetHost2Spoof(u_char *dataParam);
