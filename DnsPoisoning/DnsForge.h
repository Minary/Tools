#pragma once

#include "DnsStructs.h"

PRAW_DNS_DATA CreateDnsQueryPacket(unsigned char *host);
PRAW_DNS_DATA CreateDnsResponse_A(unsigned char *reqHostName, unsigned short transactionId, unsigned char *resolvedHostIp, unsigned long ttl);
PRAW_DNS_DATA CreateDnsResponse_CNAME(unsigned char *reqHostName, unsigned short transactionId, unsigned char *cname, unsigned char *resolvedHostIp, unsigned long ttl);


unsigned char *Add_DNS_Header(unsigned char *dataBuffer, PDNS_HEADER header, unsigned int *offset);
PQUESTION Add_QUESTION(unsigned char *dataBuffer, PQUESTION header, unsigned int *offset);
unsigned char *Add_DnsHost(unsigned char *dataBuffer, unsigned char *realHostName, unsigned int *offset);
PR_DATA Add_R_DATA(unsigned char *dataBuffer, PR_DATA responseHeader, unsigned int *offset, unsigned long ttl);
unsigned char *Add_RawBytes(unsigned char *dataBuffer, unsigned char *newData, unsigned int dataLength, unsigned int *offset);
unsigned long *Add_ResolvedIp(unsigned char *dataBuffer, unsigned char *resolvedIpAddr, unsigned int *offset);

