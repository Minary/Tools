#include <windows.h>

#include "DnsStructs.h"
#include "DnsHelper.h"


unsigned char *Add_DNS_HEADER(unsigned char *dataBuffer, PDNS_HEADER header, unsigned int *offset)
{
  unsigned char * dnsHeaderPtr = NULL;

  header->id = htons((unsigned short)GetCurrentProcessId());
  header->qr = DNS_REQUEST;
  header->opcode = 0;
  header->aa = 0;
  header->tc = 0;
  header->rd = 1;
  header->ra = 0;
  header->z = 0;
  header->ad = 0;
  header->cd = 0;
  header->rcode = 0;
  header->q_count = htons(1);
  header->ans_count = 0;
  header->auth_count = 0;
  header->add_count = 0;

  RtlCopyMemory(dataBuffer + *offset, header, sizeof(*header));
  dnsHeaderPtr = dataBuffer + *offset;
  *offset += sizeof(*header);

  return dnsHeaderPtr;
}


unsigned char *Add_DnsHost(unsigned char *dataBuffer, unsigned char *hostName, unsigned int *offset)
{
  unsigned char *dnsHostPtr = NULL;
  unsigned char dnsHostName[128];
  unsigned char tmpHostName[128];

  // Convert ASCII host name to DNS host name
  ZeroMemory(dnsHostName, sizeof(dnsHostName));
  ZeroMemory(tmpHostName, sizeof(tmpHostName));

  strncpy((char *)tmpHostName, (char *)hostName, sizeof(tmpHostName) - 1);

  ChangeTextToDnsNameFormat(dnsHostName, tmpHostName);

  // Copy DNS host name to the right position in the struct
  CopyMemory((char *)(dataBuffer + *offset), (char *)dnsHostName, strlen((char *)tmpHostName) + 1);
  dnsHostPtr = dataBuffer + *offset;
  *offset += strlen((char *)tmpHostName) + 1;

  return dnsHostPtr;
}


unsigned long *Add_ResolvedIp(unsigned char *dataBuffer, unsigned char *resolvedIpAddr, unsigned int *offset)
{
  unsigned long *resolvedIpPtr = NULL;
  unsigned long resolvedIp = inet_addr((char *)resolvedIpAddr);

  //  resolvedIp = htonl(resolvedIp);
  CopyMemory(dataBuffer + *offset, &resolvedIp, sizeof(resolvedIp));

  resolvedIpPtr = (unsigned long *)(dataBuffer + *offset);
  *offset += sizeof(resolvedIp);

  return resolvedIpPtr;
}


PQUESTION Add_QUESTION(unsigned char *dataBuffer, PQUESTION question, unsigned int *offset)
{
  PQUESTION dnsQuestionPtr = NULL;

  question->qtype = htons(TYPE_A);
  question->qclass = htons(0x01);

  CopyMemory(dataBuffer + *offset, question, sizeof(*question));
  dnsQuestionPtr = (PQUESTION)(dataBuffer + *offset);
  *offset += sizeof(*question);

  return dnsQuestionPtr;
}


PR_DATA Add_R_DATA(unsigned char *dataBuffer, PR_DATA responseHeader, unsigned int *offset)
{
  PR_DATA responseDataPtr = NULL;

  responseHeader->ttl = htonl(0x0000011d);
  responseHeader->type = htons(TYPE_A);
  responseHeader->_class = htons(0x01);
  responseHeader->data_len = htons(0x0004);

  CopyMemory(dataBuffer + *offset, responseHeader, sizeof(*responseHeader));
  responseDataPtr = (PR_DATA)(dataBuffer + *offset);
  *offset += sizeof(*responseHeader);

  return responseDataPtr;
}


unsigned char *Add_RawBytes(unsigned char *dataBuffer, unsigned char *newData, unsigned int dataLength, unsigned int *offset)
{
  unsigned char *rawBytesPtr = NULL;

  CopyMemory(dataBuffer + *offset, newData, dataLength);
  rawBytesPtr = dataBuffer + *offset;
  *offset += dataLength;

  return rawBytesPtr;
}


PRAW_DNS_DATA CreateDnsQueryPacket(unsigned char *reqHostName)
{
  unsigned char requestBuffer[1024];
  DNS_HEADER requestHeaderData;
  PDNS_HEADER requestHeaderDataPtr;
  unsigned char *dnsHostName = NULL;
  QUESTION requestQueryData;
  PQUESTION requestQueryDataPtr = NULL;
  unsigned int offset = 0;
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));

  ZeroMemory(requestBuffer, sizeof(requestBuffer));
  ZeroMemory(&requestHeaderData, sizeof(requestHeaderData));
  ZeroMemory(&requestQueryDataPtr, sizeof(requestQueryDataPtr));

  // 1. DNS_HEADER
  requestHeaderDataPtr = (PDNS_HEADER)Add_DNS_HEADER(requestBuffer, &requestHeaderData, &offset);

  // 2. DNS host name
  dnsHostName = Add_DnsHost(requestBuffer, reqHostName, &offset);

  // 3. QUESTION
  requestQueryDataPtr = Add_QUESTION(requestBuffer, &requestQueryData, &offset);
  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, offset);
  CopyMemory(rawDnsData->data, requestBuffer, offset);
  rawDnsData->dataLength = offset;

  return rawDnsData;
}


PRAW_DNS_DATA CreateDnsResponse_A(unsigned char *reqHostName, unsigned short transactionId, unsigned char *resolvedHostIp)
{
  unsigned char responseBuffer[1024];
  DNS_HEADER requestHeaderData;
  PDNS_HEADER requestHeaderDataPtr;
  unsigned char *dnsHostName = NULL;
  QUESTION requestQueryData;
  PQUESTION requestQueryDataPtr = NULL;
  PDNS_HEADER responseHeaderDataPtr = NULL;
  unsigned long *resolvedIpAddrPtr = NULL;
  unsigned int offset = 0;
  R_DATA responseData;
  PR_DATA responseHeaderPtr = NULL;
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));
  
  ZeroMemory(responseBuffer, sizeof(responseBuffer));
  ZeroMemory(&responseData, sizeof(responseData));

  // 1.1 DNS_HEADER
  requestHeaderDataPtr = (PDNS_HEADER)Add_DNS_HEADER(responseBuffer, &requestHeaderData, &offset);
  requestHeaderDataPtr->id = transactionId;
  requestHeaderDataPtr->qr = 1; // this is a response
  requestHeaderDataPtr->ans_count = htons(1); // there is one answer
  
  requestHeaderDataPtr->ra = 1;

  // 1.2 DNS host name
  dnsHostName = Add_DnsHost(responseBuffer, reqHostName, &offset);
  
  // 1.3 QUESTION
  requestQueryDataPtr = Add_QUESTION(responseBuffer, &requestQueryData, &offset);
    
  // 2.0 RESPONSE NAME: 0xC0, offset
  unsigned char nameOffset = dnsHostName - responseBuffer;
  unsigned char namePosition[] = { 0xC0, nameOffset };
  Add_RawBytes(responseBuffer, namePosition, 2, &offset);
  
  // 2.1 R_DATA
  responseHeaderPtr = Add_R_DATA(responseBuffer, &responseData, &offset);
  
  // 2.2 IP address
  resolvedIpAddrPtr = Add_ResolvedIp(responseBuffer, resolvedHostIp, &offset);
  
  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, offset);
  CopyMemory(rawDnsData->data, responseBuffer, offset);
  rawDnsData->dataLength = offset;

  return rawDnsData;
}


PRAW_DNS_DATA CreateDnsResponse_CNAME(unsigned char *reqHostName, unsigned short transactionId, unsigned char *canonicalHostName, unsigned char *resolvedHostIp)
{
  unsigned char responseBuffer[1024];
  DNS_HEADER requestHeaderData;
  PDNS_HEADER requestHeaderDataPtr;
  unsigned char *dnsHostName = NULL;
  unsigned char *dnsCanonicalName = NULL;
  QUESTION requestQueryData;
  PQUESTION requestQueryDataPtr = NULL;
  PDNS_HEADER responseHeaderDataPtr = NULL;
  unsigned long *resolvedIpAddrPtr = NULL;
  unsigned int offset = 0;
  R_DATA responseData;
  PR_DATA responseAHeaderPtr = NULL;
  PR_DATA responseCNAMEHeaderPtr = NULL;
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));
  
  ZeroMemory(responseBuffer, sizeof(responseBuffer));
  ZeroMemory(&responseData, sizeof(responseData));

  // 1.1 DNS_HEADER
  requestHeaderDataPtr = (PDNS_HEADER)Add_DNS_HEADER(responseBuffer, &requestHeaderData, &offset);
  requestHeaderDataPtr->id = transactionId;
  requestHeaderDataPtr->qr = 1; // response
  requestHeaderDataPtr->ans_count = htons(2); // Two answers. CNAME and A
  requestHeaderDataPtr->ra = 1;

  // 1.2 DNS host name
  dnsHostName = Add_DnsHost(responseBuffer, reqHostName, &offset);

  // 1.3 QUESTION
  requestQueryDataPtr = Add_QUESTION(responseBuffer, &requestQueryData, &offset);

  // 2.0 RESPONSE CNAME: 0xC0, offset
  unsigned char nameOffset = dnsHostName - responseBuffer;
  unsigned char namePosition[] = { 0xC0, nameOffset };
  Add_RawBytes(responseBuffer, namePosition, 2, &offset);
  
  // 2.1 R_DATA
  responseCNAMEHeaderPtr = Add_R_DATA(responseBuffer, &responseData, &offset);
  responseCNAMEHeaderPtr->type = htons(TYPE_CNAME);
  responseCNAMEHeaderPtr->data_len = htons((unsigned short)strlen((char *)canonicalHostName) + 2);

  // 2.2 
  dnsCanonicalName = Add_DnsHost(responseBuffer, canonicalHostName, &offset);

  // 3.0 RESPONSE A: 0xC0, offset
  unsigned char cnameOffset = dnsCanonicalName - responseBuffer;
  unsigned char cnamePosition[] = { 0xC0, cnameOffset };
  Add_RawBytes(responseBuffer, cnamePosition, 2, &offset);

  // 3.1 R_DATA
  responseAHeaderPtr = Add_R_DATA(responseBuffer, &responseData, &offset);
  responseAHeaderPtr->type = htons(TYPE_A);
  responseAHeaderPtr->data_len = htons(4);

  // 3.2 IP address
  resolvedIpAddrPtr = Add_ResolvedIp(responseBuffer, resolvedHostIp, &offset);
  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, offset);
  CopyMemory(rawDnsData->data, responseBuffer, offset);
  rawDnsData->dataLength = offset;

  return rawDnsData;
}