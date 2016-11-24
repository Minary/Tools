#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <Shlwapi.h>
#include <stdarg.h>
#include <sys/timeb.h>
#include <icmpapi.h>

#include "APESniffer.h"
//#include "PacketProxy.h"
//#include "GSniffer.h"
#include "LinkedListSystems.h"
#include "LinkedListConnections.h"
#include "NetworkFunctions.h"




/*
*
*
*/
void Mac2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0 && pMAC != NULL && pOutputLen >= MAX_MAC_LEN)
    snprintf((char *)pOutput, pOutputLen - 1, "%02X-%02X-%02X-%02X-%02X-%02X", pMAC[0], pMAC[1], pMAC[2], pMAC[3], pMAC[4], pMAC[5]);
}

void Ip2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
    snprintf((char *)pOutput, pOutputLen, "%d.%d.%d.%d", pIP[0], pIP[1], pIP[2], pIP[3]);
}



/*
*
*
*/
void String2Mac(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pInput, int pInputLen)
{
  //if (pInput != NULL && pInputLen > 0 && pMAC != NULL)
  //	if (sscanf((char *)pInput, "%hh0x:%hh0x:%hh0x:%hh0x:%hh0x:%hh0x", &pMAC[0], &pMAC[1], &pMAC[2], &pMAC[3], &pMAC[4], &pMAC[5]) != 6)
  //		sscanf((char *)pInput, "%hh0x:%hh0x:%hh0x:%hh0x:%hh0x:%hh0x", &pMAC[0], &pMAC[1], &pMAC[2], &pMAC[3], &pMAC[4], &pMAC[5]);
  if (pInput != NULL && pInputLen > 0 && pMAC != NULL)
    if (sscanf((char *)pInput, "%02X:%02X:%02X:%02X:%02X:%02X", &pMAC[0], &pMAC[1], &pMAC[2], &pMAC[3], &pMAC[4], &pMAC[5]) != 6)
      sscanf((char *)pInput, "%02X-%02X-%02X-%02X-%02X-%02X", &pMAC[0], &pMAC[1], &pMAC[2], &pMAC[3], &pMAC[4], &pMAC[5]);
}



/*
*
*
*/
int String2Ip(unsigned char pIP[BIN_IP_LEN], unsigned char *pInput, int pInputLen)
{
  int lRetVal = 1;
  unsigned char lIP[BIN_IP_LEN];

  ZeroMemory(lIP, BIN_IP_LEN);
  ZeroMemory(pIP, BIN_IP_LEN);

  //if (pIP != NULL && pInput != NULL && pInputLen > 0)
  //  if (sscanf((char *) pInput, "%c.%c.%c.%c", &pIP[0], &pIP[1], &pIP[2], &pIP[3]) == 4)
  //    if ((lIP[0] | lIP[1] | lIP[2] | lIP[3]) < 255)
  //      if (strspn((char *) pInput, "0123456789.") == strlen((char *) pInput))
  //        lRetVal = 0;

  if (pIP != NULL && pInput != NULL && pInputLen > 0)
    if (sscanf((char *)pInput, "%d.%d.%d.%d", &pIP[0], &pIP[1], &pIP[2], &pIP[3]) == 4)
      if ((lIP[0] | lIP[1] | lIP[2] | lIP[3]) < 255)
        if (strspn((char *)pInput, "0123456789.") == strlen((char *)pInput))
          lRetVal = 0;

  return lRetVal;
}




/*
*
*
*/
int GetAliasByIfcIndex(int pIfcIndex, char *pAliasBuf, int pBufLen)
{
  int lRetVal = NOK;
  MIB_IF_ROW2 lIfcRow;

  if (pAliasBuf != NULL && pBufLen > 0)
  {
    SecureZeroMemory((PVOID)&lIfcRow, sizeof(MIB_IF_ROW2));
    lIfcRow.InterfaceIndex = pIfcIndex;

    if (GetIfEntry2(&lIfcRow) == NO_ERROR)
    {
      snprintf(pAliasBuf, pBufLen - 1, "%ws", lIfcRow.Alias);
    }
  }

  return lRetVal;
}




/*
*
*
*/
void SetMacStatic(char *pIfcAlias, char *pIP, char *pMAC)
{
  char lTemp[MAX_BUF_SIZE + 1];
  char lGWIPstring[MAX_BUF_SIZE + 1];
  char *lTmpPtr = NULL;

  printf("SetMACStatic(0) : arp -d %s & netsh interface ip add neighbors \"%s\" %s %s\n\n", pIP, pIfcAlias, pIP, pMAC);

  //Set IP static
  if (pIfcAlias != NULL && pIP != NULL && pMAC != NULL)
  {
    ZeroMemory(lTemp, sizeof(lTemp));
    ZeroMemory(lGWIPstring, sizeof(lGWIPstring));

    // The arp tool needs '-' as octet separator
    if (strchr(pMAC, ':'))
      for (lTmpPtr = pMAC; lTmpPtr[0] != NULL; lTmpPtr++)
        if (lTmpPtr[0] == ':')
          lTmpPtr[0] = '-';

    printf("SetMACStatic(1) : arp -d %s & netsh interface ip add neighbors \"%s\" %s %s\n\n", pIP, pIfcAlias, pIP, pMAC);

    snprintf(lTemp, sizeof(lTemp) - 1, "arp -d %s & netsh interface ip add neighbors \"%s\" %s %s", pIP, pIfcAlias, pIP, pMAC);
    ExecCommand(lTemp);
  }
}




/*
*
*
*/
void RemoveMac(char *pIfcAlias, char *pIPAddr)
{
  char lTemp[MAX_BUF_SIZE + 1];

  if (pIfcAlias != NULL && pIPAddr != NULL)
  {
    ZeroMemory(lTemp, sizeof(lTemp) - 1);
    snprintf(lTemp, sizeof(lTemp) - 1, "netsh interface ip delete neighbors \"%s\" %s", pIfcAlias, pIPAddr);
    ExecCommand(lTemp);

    ZeroMemory(lTemp, sizeof(lTemp) - 1);
    snprintf(lTemp, sizeof(lTemp) - 1, "arp -d %s", pIPAddr);
    ExecCommand(lTemp);
  }
}




/*
*
*
*/
void DumpPacket(unsigned char *pPktData, int pPktLen, char *pTitlestring, const struct pcap_pkthdr *pPktHdr)
{
  struct tm *lTime;
  char lTimestr[128];
  time_t local_tv_sec;

  PETHDR pEthHdr = (PETHDR)pPktData;
  PARPHDR pARPData = NULL;
  PIPHDR pIPHdr = NULL;
  PICMPHDR pICMPHdr = NULL;
  unsigned long lIPID = 0;
  int lIPHdrLen = 0;
  unsigned char lSMAC[MAX_BUF_SIZE + 1];
  unsigned char lDMAC[MAX_BUF_SIZE + 1];
  unsigned char lSIP[MAX_BUF_SIZE + 1];
  unsigned char lDIP[MAX_BUF_SIZE + 1];
  unsigned char lTCPFlags[MAX_BUF_SIZE + 1];
  char lIPProto[MAX_BUF_SIZE + 1];
  char lData[1600 + 1];
  char lRealData[1600 + 1];
  int lSPort = 0;
  int lDPort = 0;
  PTCPHDR pTCPHdr = NULL;
  PUDPHDR pUDPHdr = NULL;
  int lTotLen = 0;
  int lTCPHdrLen = 0;
  int lUDPHdrLen = 0;
  int lTCPDataLen = 0;
  int lUDPDataLen = 0;
  int lICMPDataLen = 0;
  char lAck = '.';
  char lSyn = '.';
  char lFin = '.';
  char lUrg = '.';
  char lPsh = '.';
  char lRst = '.';
  SYSTEMTIME lSysTime;



  GetSystemTime(&lSysTime);

  // Get the time/date stamp
  local_tv_sec = pPktHdr->ts.tv_sec;
  lTime = localtime(&local_tv_sec);
  strftime(lTimestr, sizeof(lTimestr), "%H:%M:%S", lTime);

  if (pPktData == NULL || pPktLen <= 0 || pPktHdr == NULL || pPktHdr->len <= 0)
  {
    printf("\n[%s - INVALID DATA - %d:%d:%d.%.3d]\n", pTitlestring, lSysTime.wHour, lSysTime.wMinute, lSysTime.wSecond, lSysTime.wMilliseconds);
    return;
  }

  if (htons(pEthHdr->ether_type) == ETHERTYPE_ARP)
  {
    ZeroMemory(lSMAC, sizeof(lSMAC));
    ZeroMemory(lDMAC, sizeof(lDMAC));
    ZeroMemory(lSIP, sizeof(lSIP));
    ZeroMemory(lDIP, sizeof(lDIP));

    printf("ARP\n");
  }
  else if (htons(pEthHdr->ether_type) == ETHERTYPE_IP)
  {
    pIPHdr = (PIPHDR)(pPktData + 14);
    lIPHdrLen = (pIPHdr->ver_ihl & 0xf) * 4;
    lTotLen = ntohs(pIPHdr->tlen);

    ZeroMemory(lSIP, sizeof(lSIP));
    ZeroMemory(lDIP, sizeof(lDIP));
    ZeroMemory(lSMAC, sizeof(lSMAC));
    ZeroMemory(lDMAC, sizeof(lDMAC));

    lIPID = pIPHdr->ttl;
    Mac2String(pEthHdr->ether_shost, lSMAC, sizeof(lSMAC));
    Mac2String(pEthHdr->ether_dhost, lDMAC, sizeof(lDMAC));
    snprintf((char *)lSIP, sizeof(lSIP) - 1, "%d.%d.%d.%d", pIPHdr->saddr.byte1, pIPHdr->saddr.byte2, pIPHdr->saddr.byte3, pIPHdr->saddr.byte4);
    snprintf((char *)lDIP, sizeof(lDIP) - 1, "%d.%d.%d.%d", pIPHdr->daddr.byte1, pIPHdr->daddr.byte2, pIPHdr->daddr.byte3, pIPHdr->daddr.byte4);

    ZeroMemory(lData, sizeof(lData));
    ZeroMemory(lRealData, sizeof(lRealData));
    ZeroMemory(lTCPFlags, sizeof(lTCPFlags));


    // UDP packet
    if (pIPHdr->proto == IP_PROTO_UDP)
    {
      snprintf(lIPProto, sizeof(lIPProto) - 1, "UDP %d", pIPHdr->proto);
      pUDPHdr = (PUDPHDR)((unsigned char*)pIPHdr + lIPHdrLen);
      lSPort = ntohs(pUDPHdr->sport);
      lDPort = ntohs(pUDPHdr->dport);

      lUDPHdrLen = ntohs(pIPHdr->tlen);
      lUDPDataLen = lTotLen - sizeof(IPHDR) - sizeof(UDPHDR);

      if (lUDPDataLen > 1590)
      {
        memcpy(lData, (unsigned char *)pUDPHdr + sizeof(UDPHDR), 1590);
        stringify((unsigned char *)lData, 1590, (unsigned char *)lRealData);
      }
      else if (lUDPDataLen > 0)
      {
        memcpy(lData, (unsigned char *)pUDPHdr + sizeof(UDPHDR), lUDPDataLen);
        stringify((unsigned char *)lData, lUDPDataLen, (unsigned char *)lRealData);
      }


      // TCP packet
    }
    else if (pIPHdr->proto == IP_PROTO_TCP)
    {
      strcpy(lIPProto, "TCP");
      pTCPHdr = (PTCPHDR)((unsigned char*)pIPHdr + lIPHdrLen);
      lSPort = ntohs(pTCPHdr->sport);
      lDPort = ntohs(pTCPHdr->dport);

      if (pTCPHdr->ack != 0) lAck = 'A';
      if (pTCPHdr->syn != 0) lSyn = 'S';
      if (pTCPHdr->fin != 0) lFin = 'F';
      if (pTCPHdr->rst != 0) lRst = 'R';
      if (pTCPHdr->psh != 0) lPsh = 'P';
      if (pTCPHdr->urg != 0) lUrg = 'U';

      snprintf((char *)lTCPFlags, sizeof(lTCPFlags) - 1, "%c%c%c%c%c%c", lAck, lSyn, lFin, lRst, lPsh, lUrg);

      lTCPHdrLen = pTCPHdr->doff * 4;
      lTCPDataLen = lTotLen - lIPHdrLen - lTCPHdrLen;


      if (lTCPDataLen > 1590)
      {
        memcpy(lData, (unsigned char *)pTCPHdr + lTCPHdrLen, 1590);
        stringify((unsigned char *)lData, 1590, (unsigned char *)lRealData);
      }
      else if (lTCPDataLen > 0)
      {
        memcpy(lData, (unsigned char *)pTCPHdr + lTCPHdrLen, lTCPDataLen);
        stringify((unsigned char *)lData, lTCPDataLen, (unsigned char *)lRealData);
      }


      // ICMP packet
    }
    else if (pIPHdr->proto == IP_PROTO_ICMP)
    {
      strcpy(lIPProto, "ICMP");
      pICMPHdr = (PICMPHDR)((unsigned char*)pIPHdr + lIPHdrLen);

      ZeroMemory(lData, sizeof(lData));
      ZeroMemory(lRealData, sizeof(lRealData));

      lICMPDataLen = lTotLen - sizeof(IPHDR) - sizeof(ICMPHDR);
      memcpy(lData, (unsigned char *)pICMPHdr + sizeof(ICMPHDR), lICMPDataLen);
      snprintf((char *)lTCPFlags, sizeof(lTCPFlags), "%d", pICMPHdr->sequence);


      if (lICMPDataLen > 1590)
      {
        printf("[LEN %d too big]\n", lICMPDataLen);
        memcpy(lData, (unsigned char *)pICMPHdr + lICMPDataLen, 1590);
        stringify((unsigned char *)lData, 1590, (unsigned char *)lRealData);
      }
      else if (lTCPDataLen > 0)
      {
        printf("LEN %d size ok\n", lICMPDataLen);
        memcpy(lData, (unsigned char *)pICMPHdr + sizeof(ICMPHDR), lICMPDataLen);
        //        stringify(lData, lTCPDataLen, lRealData);
      }
    }
    else
    {
      strcpy(lIPProto, "UNKNOWN");
    }

    printf("\n[%s - %d bytes - %d:%d:%d.%.3d]\n", pTitlestring, pPktLen, lSysTime.wHour, lSysTime.wMinute, lSysTime.wSecond, lSysTime.wMilliseconds);
    printf("  %s  %d bytes - %d TTL - %s\n", lIPProto, lTotLen, lIPID, lTCPFlags);
    printf("  %s -> %s\n", lSMAC, lDMAC);
    printf("  %s:%d -> %s:%d\n", lSIP, lSPort, lDIP, lDPort);
    printf("%s\n", lRealData);
  }
  else
  {
    printf("OOOPS Protocol is %x\n", pEthHdr->ether_type);
  }
}


