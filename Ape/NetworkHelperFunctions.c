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

#include "APE.h"
#include "PacketHandlerArpMitm.h"
#include "LinkedListTargetSystems.h"
#include "NetworkHelperFunctions.h"



void MacBin2String(unsigned char macAddrParam[BIN_MAC_LEN], unsigned char *outputParam, int outputLengthParam)
{
  if (outputParam && outputLengthParam > 0 && macAddrParam != NULL && outputLengthParam >= MAX_MAC_LEN)
  {
    snprintf((char *)outputParam, outputLengthParam - 1, "%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX", macAddrParam[0], macAddrParam[1], macAddrParam[2], macAddrParam[3], macAddrParam[4], macAddrParam[5]);
  }
}


void IpBin2String(unsigned char ipAddrParam[BIN_IP_LEN], unsigned char *outputParam, int outputLengthParam)
{
  if (outputParam && outputLengthParam > 0)
  {
    snprintf((char *)outputParam, outputLengthParam, "%d.%d.%d.%d", ipAddrParam[0], ipAddrParam[1], ipAddrParam[2], ipAddrParam[3]);
  }
}


void MacString2Bin(unsigned char macAddrParam[BIN_MAC_LEN], unsigned char *inputParam, int inputLengthParam)
{
  if (inputParam != NULL && inputLengthParam > 0 && macAddrParam != NULL)
  {
    if (sscanf((char *)inputParam, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", &macAddrParam[0], &macAddrParam[1], &macAddrParam[2], &macAddrParam[3], &macAddrParam[4], &macAddrParam[5]) != 6)
    {
      sscanf((char *)inputParam, "%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX", &macAddrParam[0], &macAddrParam[1], &macAddrParam[2], &macAddrParam[3], &macAddrParam[4], &macAddrParam[5]);
    }
  }
}


int IpString2Bin(unsigned char ipParam[BIN_IP_LEN], unsigned char *inputParam, int inputLengthParam)
{
  int retVal = 1;
  unsigned char ipAddrBin[BIN_IP_LEN];

  ZeroMemory(ipAddrBin, BIN_IP_LEN);
  ZeroMemory(ipParam, BIN_IP_LEN);
  
  if (ipParam == NULL || inputParam == NULL || inputLengthParam <= 0)
  {
    return retVal;
  }

  if (sscanf((char *)inputParam, "%hhd.%hhd.%hhd.%hhd", &ipParam[0], &ipParam[1], &ipParam[2], &ipParam[3]) != 4)
  {
    return retVal;
  }

  if ((ipAddrBin[0] | ipAddrBin[1] | ipAddrBin[2] | ipAddrBin[3]) >= 255)
  {
    return retVal;
  }

  if (strspn((char *)inputParam, "0123456789.") == strlen((char *)inputParam))
  {
    retVal = 0;
  }

  return retVal;
}


BOOL GetAliasByIfcIndex(int ifcIndexParam, char *aliasBufferParam, int bufferLengthParam)
{
  BOOL retVal = FALSE;
  MIB_IF_ROW2 ifcRow;

  if (aliasBufferParam == NULL || bufferLengthParam <= 0)
  {
    return retVal;
  }

  SecureZeroMemory((PVOID) &ifcRow, sizeof(MIB_IF_ROW2) );
  ifcRow.InterfaceIndex = ifcIndexParam;

  if (GetIfEntry2(&ifcRow) == NO_ERROR) 
  {
    snprintf(aliasBufferParam, bufferLengthParam-1, "%ws", ifcRow.Alias);
    retVal = TRUE;
  }

  return retVal;
}


void SetMacStatic(char *ifcAliasParam, char *ipAddrParam, char *macAddrParam)
{
  char temp[MAX_BUF_SIZE + 1];
  char gatewayIpAddrString[MAX_BUF_SIZE + 1];
  char *tempPtr = NULL;

  printf("SetMacStatic(0): arp -d %s & netsh interface ip add neighbors \"%s\" %s %s\n", ipAddrParam, ifcAliasParam, ipAddrParam, macAddrParam);

  //Set IP static
  if (ifcAliasParam == NULL ||
      ipAddrParam == NULL ||
      macAddrParam != NULL)
  {
    goto END;
  }

  ZeroMemory(temp, sizeof(temp));
  ZeroMemory(gatewayIpAddrString, sizeof(gatewayIpAddrString));

  // The arp tool needs '-' as octet separator
  if (strchr(macAddrParam, ':'))
  {
    goto END;
  }

  for (tempPtr = macAddrParam; tempPtr[0] != NULL; tempPtr++)
  {
    if (tempPtr[0] == ':')
    {
      tempPtr[0] = '-';
    }
  }

END:

  printf("SetMACStatic(1): arp -d %s & netsh interface ip add neighbors \"%s\" %s %s\n\n", ipAddrParam, ifcAliasParam, ipAddrParam, macAddrParam);
  snprintf(temp, sizeof(temp) - 1, "arp -d %s & netsh interface ip add neighbors \"%s\" %s %s", ipAddrParam, ifcAliasParam, ipAddrParam, macAddrParam);
  ExecCommand(temp);
}


void RemoveMacFromCache(char *ifcAliasParam, char *ipAddrParam)
{
  char tempBuffer[MAX_BUF_SIZE + 1];

  if (ifcAliasParam == NULL || ipAddrParam == NULL)
  {
    return;
  }

  ZeroMemory(tempBuffer, sizeof(tempBuffer)-1);
  snprintf(tempBuffer, sizeof(tempBuffer) - 1, "netsh interface ip delete neighbors \"%s\" %s", ifcAliasParam, ipAddrParam);
  ExecCommand(tempBuffer);

  ZeroMemory(tempBuffer, sizeof(tempBuffer)-1);
  snprintf(tempBuffer, sizeof(tempBuffer) - 1, "arp -d %s", ipAddrParam);
  ExecCommand(tempBuffer);
}


void DumpPacket(unsigned char *pktDataParam, int pktLengthParam, char *titleStringParam, const struct pcap_pkthdr *pktHdrParam)
{
  struct tm *time;
  char timeStr[128];
  time_t local_tv_sec;

  PETHDR ethrHdrPtr = (PETHDR) pktDataParam;
  PARPHDR arpData = NULL;
  PIPHDR ipHdr = NULL;
  PICMPHDR icmpHdr = NULL;
  unsigned long ipId = 0;
  int ipHdrLength = 0;
  unsigned char srcMacAddr[MAX_BUF_SIZE + 1];
  unsigned char dstMacAddr[MAX_BUF_SIZE + 1];
  unsigned char srcIpAddr[MAX_BUF_SIZE + 1];
  unsigned char dstIpAddr[MAX_BUF_SIZE + 1];
  unsigned char tcpFlags[MAX_BUF_SIZE + 1];
  char ipProto[MAX_BUF_SIZE + 1];
  char data[1600 + 1];
  char realData[1600 + 1];
  int srcPort = 0;
  int dstPort = 0;
  PTCPHDR tcpHdrPdr = NULL;
  PUDPHDR udpHdrPtr = NULL;
  int totalLength = 0;
  int tcpHdrLength = 0;
  int udpHdrLength = 0;
  int tcpDataLength = 0;
  int udpDataLength = 0;
  int icmpDataLength = 0;
  char ackFlag = '.';
  char synFlag = '.';
  char finFlag = '.';
  char urgFlag = '.';
  char pshFlag = '.';
  char rstFlag = '.';
  SYSTEMTIME sysTime;

  GetSystemTime(&sysTime);

  // Get the time/date stamp
  local_tv_sec = pktHdrParam->ts.tv_sec;
  time = localtime(&local_tv_sec);
  strftime(timeStr, sizeof(timeStr), "%H:%M:%S", time);

  if (pktDataParam == NULL || pktLengthParam <= 0 || pktHdrParam == NULL || pktHdrParam->len <= 0)
  {
    printf("\n[%s - INVALID DATA - %d:%d:%d.%.3d]\n", titleStringParam, sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wMilliseconds);
    return;
  }

  if (htons(ethrHdrPtr->ether_type) == ETHERTYPE_ARP)
  {
    ZeroMemory(srcMacAddr, sizeof(srcMacAddr));
    ZeroMemory(dstMacAddr, sizeof(dstMacAddr));
    ZeroMemory(srcIpAddr, sizeof(srcIpAddr));
    ZeroMemory(dstIpAddr, sizeof(dstIpAddr));

    printf("ARP\n");
  }
  else if (htons(ethrHdrPtr->ether_type) == ETHERTYPE_IP)
  {
    ipHdr = (PIPHDR) (pktDataParam + 14);
    ipHdrLength = (ipHdr->ver_ihl & 0xf) * 4;
    totalLength = ntohs(ipHdr->tlen);

    ZeroMemory(srcIpAddr, sizeof(srcIpAddr));
    ZeroMemory(dstIpAddr, sizeof(dstIpAddr));
    ZeroMemory(srcMacAddr, sizeof(srcMacAddr));
    ZeroMemory(dstMacAddr, sizeof(dstMacAddr));

    ipId = ipHdr->ttl;
    MacBin2String(ethrHdrPtr->ether_shost, srcMacAddr, sizeof(srcMacAddr));
    MacBin2String(ethrHdrPtr->ether_dhost, dstMacAddr, sizeof(dstMacAddr));
    snprintf((char *) srcIpAddr, sizeof(srcIpAddr) - 1, "%d.%d.%d.%d", ipHdr->saddr.byte1, ipHdr->saddr.byte2, ipHdr->saddr.byte3, ipHdr->saddr.byte4);
    snprintf((char *) dstIpAddr, sizeof(dstIpAddr) - 1, "%d.%d.%d.%d", ipHdr->daddr.byte1, ipHdr->daddr.byte2, ipHdr->daddr.byte3, ipHdr->daddr.byte4);

    ZeroMemory(data, sizeof(data));
    ZeroMemory(realData, sizeof(realData));
    ZeroMemory(tcpFlags, sizeof(tcpFlags));


    // UDP packet
    if (ipHdr->proto == IP_PROTO_UDP)
    {
      snprintf(ipProto, sizeof(ipProto)-1, "UDP %d", ipHdr->proto);
      udpHdrPtr = (PUDPHDR) ((unsigned char*) ipHdr + ipHdrLength);
      srcPort = ntohs(udpHdrPtr->sport);
      dstPort = ntohs(udpHdrPtr->dport);

      udpHdrLength = ntohs(ipHdr->tlen);
      udpDataLength = totalLength - sizeof(IPHDR) - sizeof(UDPHDR);

      if (udpDataLength > 1590)
      {
        memcpy(data, (unsigned char *) udpHdrPtr + sizeof(UDPHDR), 1590);
        Stringify((unsigned char *) data, 1590, (unsigned char *) realData);
      }
      else if (udpDataLength > 0) 
      {
        memcpy(data, (unsigned char *) udpHdrPtr + sizeof(UDPHDR), udpDataLength);
        Stringify((unsigned char *) data, udpDataLength, (unsigned char *) realData);
      }


    // TCP packet
    }
    else if (ipHdr->proto == IP_PROTO_TCP)
    {
      strcpy(ipProto, "TCP");
      tcpHdrPdr = (PTCPHDR) ((unsigned char*) ipHdr + ipHdrLength);
      srcPort = ntohs(tcpHdrPdr->sport);
      dstPort = ntohs(tcpHdrPdr->dport);

      if (tcpHdrPdr->ack != 0) ackFlag = 'A';
      if (tcpHdrPdr->syn != 0) synFlag = 'S';
      if (tcpHdrPdr->fin != 0) finFlag = 'F';
      if (tcpHdrPdr->rst != 0) rstFlag = 'R';
      if (tcpHdrPdr->psh != 0) pshFlag = 'P';
      if (tcpHdrPdr->urg != 0) urgFlag = 'U';

      snprintf((char *) tcpFlags, sizeof(tcpFlags)-1, "%c%c%c%c%c%c", ackFlag, synFlag, finFlag, rstFlag, pshFlag, urgFlag);

      tcpHdrLength = tcpHdrPdr->doff * 4;
      tcpDataLength = totalLength - ipHdrLength - tcpHdrLength;


      if (tcpDataLength > 1590)
      {
        memcpy(data, (unsigned char *) tcpHdrPdr + tcpHdrLength, 1590);
        Stringify((unsigned char *) data, 1590, (unsigned char *) realData);
      }
      else if (tcpDataLength > 0) 
      {
        memcpy(data, (unsigned char *) tcpHdrPdr + tcpHdrLength, tcpDataLength);
        Stringify((unsigned char *) data, tcpDataLength, (unsigned char *) realData);
      }

    // ICMP packet
    }
    else if (ipHdr->proto == IP_PROTO_ICMP)
    {
      strcpy(ipProto, "ICMP");
      icmpHdr = (PICMPHDR) ((unsigned char*) ipHdr + ipHdrLength);

      ZeroMemory(data, sizeof(data));
      ZeroMemory(realData, sizeof(realData));

      icmpDataLength = totalLength - sizeof(IPHDR) - sizeof(ICMPHDR);
      memcpy(data, (unsigned char *) icmpHdr + sizeof(ICMPHDR), icmpDataLength);
      snprintf((char *) tcpFlags, sizeof(tcpFlags), "%d", icmpHdr->sequence);
      
      if (icmpDataLength > 1590)
      {
        printf("[LEN %d too big]\n", icmpDataLength);
        memcpy(data, (unsigned char *) icmpHdr + icmpDataLength, 1590);
        Stringify((unsigned char *) data, 1590, (unsigned char *) realData);
      }
      else if (tcpDataLength > 0) 
      {
        printf("LEN %d size ok\n", icmpDataLength);
        memcpy(data, (unsigned char *) icmpHdr + sizeof(ICMPHDR), icmpDataLength);
        //        stringify(lData, lTCPDataLen, lRealData);
      } 
    }
    else
    {
      strcpy(ipProto, "UNKNOWN");
    }

    printf("\n[%s - %d bytes - %d:%d:%d.%.3d]\n", titleStringParam, pktLengthParam, sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wMilliseconds);
    printf("  %s  %d bytes - %d TTL - %s\n", ipProto, totalLength, ipId, tcpFlags);
    printf("  %s -> %s\n", srcMacAddr, dstMacAddr);
    printf("  %s:%d -> %s:%d\n", srcIpAddr, srcPort, dstIpAddr, dstPort);
    printf("%s\n", realData);
  }
  else
  {
    printf("OOOPS Protocol is %x\n", ethrHdrPtr->ether_type);
  }
}


unsigned short in_cksum(unsigned short *addr, int length)
{
  register int sum = 0;
  register unsigned short *w = addr;
  register int numLeft = length;
  unsigned short checkSum = 0;

  // using a 32 bit accumulator (sum), u16_add sequential 16 bit words to it, 
  // and at the end, fold back all the carry bits from the top 16 bits into
  // the lower 16 bits.
  while (numLeft > 1)
  {
    sum += *w++;
    numLeft -= 2;
  }

  //handle odd byte
  if (numLeft == 1)
  {
    *(unsigned char *)(&checkSum) = *(unsigned char *)w;
    sum += checkSum;
  }

  // u16_add back carry outs from top 16 bits to low 16 bits 
  sum = (sum >> 16) + (sum & 0xffff);    // u16_add high 16 to low 16 
  sum += (sum >> 16);                     // u16_add carry 
  checkSum = ~sum;                        // truncate to 16 bits

  return checkSum;
}

