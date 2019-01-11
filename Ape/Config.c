#include <Shlwapi.h>
#include <stdio.h>
#include <Windows.h>

#include "APE.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "LinkedListFirewallRules.h"
#include "LinkedListTargetSystems.h"
#include "Logging.h"
#include "NetworkHelperFunctions.h"


extern PRULENODE gFwRulesList;
extern PSYSNODE gTargetSystemsList;
extern PHOSTNODE gDnsSpoofingList;


void PrintConfig(SCANPARAMS scanParamsParam)
{
  printf("Local IP :\t%d.%d.%d.%d\n", scanParamsParam.LocalIpBin[0], scanParamsParam.LocalIpBin[1], scanParamsParam.LocalIpBin[2], scanParamsParam.LocalIpBin[3]);
  printf("Local MAC :\t%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", scanParamsParam.LocalMacBin[0], scanParamsParam.LocalMacBin[1], scanParamsParam.LocalMacBin[2],
    scanParamsParam.LocalMacBin[3], scanParamsParam.LocalMacBin[4], scanParamsParam.LocalMacBin[5]);
  printf("GW MAC :\t%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", scanParamsParam.GatewayMacBin[0], scanParamsParam.GatewayMacBin[1], scanParamsParam.GatewayMacBin[2],
    scanParamsParam.GatewayMacBin[3], scanParamsParam.GatewayMacBin[4], scanParamsParam.GatewayMacBin[5]);
  printf("GW IP :\t\t%d.%d.%d.%d\n", scanParamsParam.GatewayIpBin[0], scanParamsParam.GatewayIpBin[1], scanParamsParam.GatewayIpBin[2], scanParamsParam.GatewayIpBin[3]);
  printf("Start IP :\t%d.%d.%d.%d\n", scanParamsParam.StartIpBin[0], scanParamsParam.StartIpBin[1], scanParamsParam.StartIpBin[2], scanParamsParam.StartIpBin[3]);
  printf("Stop IP :\t%d.%d.%d.%d\n", scanParamsParam.StopIpBin[0], scanParamsParam.StopIpBin[1], scanParamsParam.StopIpBin[2], scanParamsParam.StopIpBin[3]);
}


int ParseTargetHostsConfigFile(char *targetsFile)
{
  int retVal = 0;
  unsigned char ipStr[MAX_IP_LEN];
  unsigned char macStr[MAX_MAC_LEN];
  unsigned char ipBin[BIN_IP_LEN];
  unsigned char macBin[BIN_MAC_LEN];
  FILE *fileHandle = NULL;
  char tempLine[MAX_BUF_SIZE + 1];

  if (targetsFile == NULL)
  {
    goto END;
  }

  if (!PathFileExists(targetsFile))
  {
    goto END;
  }

  if ((fileHandle = fopen(targetsFile, "r")) == NULL)
  {
    goto END;
  }

  ZeroMemory(tempLine, sizeof(tempLine));
  ZeroMemory(ipStr, sizeof(ipStr));
  ZeroMemory(macStr, sizeof(macStr));
  ZeroMemory(ipBin, sizeof(ipBin));
  ZeroMemory(macBin, sizeof(macBin));

  while (fgets(tempLine, sizeof(tempLine), fileHandle) != NULL)
  {
    // Remove trailing CR/LF
    while (tempLine[strlen(tempLine) - 1] == '\r' || tempLine[strlen(tempLine) - 1] == '\n')
    {
      tempLine[strlen(tempLine) - 1] = '\0';
    }

    // parse values and add them to the list.
    if (sscanf(tempLine, "%[^,],%s", ipStr, macStr) == 2)
    {
      MacString2Bin(macBin, macStr, strnlen((char *)macStr, sizeof(macStr) - 1));
      IpString2Bin(ipBin, ipStr, strnlen((char *)ipStr, sizeof(ipStr) - 1));

      AddToSystemsList(&gTargetSystemsList, macBin, (char *)ipStr, ipBin);
      retVal++;
      LogMsg(DBG_MEDIUM, "ParseTargetHostsConfigFile(): New system added :  %s/%s", macStr, ipStr);
    }

    ZeroMemory(tempLine, sizeof(tempLine));
    ZeroMemory(ipStr, sizeof(ipStr));
    ZeroMemory(macStr, sizeof(macStr));
    ZeroMemory(ipBin, sizeof(ipBin));
    ZeroMemory(macBin, sizeof(macBin));
  }

END:

  if (fileHandle != NULL)
  {
    fclose(fileHandle);
  }

  return retVal;
}


int ParseFirewallConfigFile(char *firewallRulesFile)
{
  int retVal = 0;
  unsigned short srcPortLower = 0;
  unsigned short srcPortUpper = 0;
  unsigned short dstPortLower = 0;
  unsigned short dstPortUpper = 0;
  char srcIpStr[MAX_IP_LEN] = { 0 };
  char dstIPStr[MAX_IP_LEN] = { 0 };
  FILE *fileHandle = NULL;
  int funcRetVal = 0;
  char protocol[12] = { 0 };
  char tempBuffer[MAX_BUF_SIZE + 1] = { 0 };
  PRULENODE tempNode = NULL;

  if (firewallRulesFile == NULL)
  {
    goto END;
  }

  if (!PathFileExists(firewallRulesFile))
  {
    goto END;
  }

  if ((fileHandle = fopen(FILE_FIREWALL_RULES, "r")) == NULL)
  {
    goto END;
  }

  while (!feof(fileHandle))
  {
    fgets(tempBuffer, sizeof(tempBuffer), fileHandle);
    ZeroMemory(srcIpStr, sizeof(srcIpStr));
    ZeroMemory(dstIPStr, sizeof(dstIPStr));

    // Remove trailing CR/LF
    while (tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] == '\r' || tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] == '\n')
    {
      tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] = 0;
    }

    if ((funcRetVal = sscanf(tempBuffer, "%[^:]:%[^:]:%hu:%hu:%[^:]:%hu:%hu", protocol, srcIpStr, &srcPortLower, &srcPortUpper, dstIPStr, &dstPortLower, &dstPortUpper)) != 7 ||
      tempBuffer[0] == '#')
    {
      continue;
    }

    if ((tempNode = (PRULENODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RULENODE))) == NULL)
    {
      continue;
    }

    ZeroMemory(tempNode, sizeof(RULENODE));
    tempNode->DstIPBin = inet_addr(dstIPStr);
    strncpy(tempNode->DstIPStr, dstIPStr, sizeof(tempNode->DstIPStr) - 1);
    tempNode->DstPortLower = dstPortLower;
    tempNode->DstPortUpper = dstPortUpper;

    tempNode->SrcIPBin = inet_addr(srcIpStr);
    strncpy(tempNode->SrcIPStr, srcIpStr, sizeof(tempNode->SrcIPStr) - 1);
    tempNode->SrcPortLower = srcPortLower;
    tempNode->SrcPortUpper = srcPortUpper;

    strncpy(tempNode->Protocol, protocol, sizeof(tempNode->Protocol) - 1);
    snprintf(tempNode->Descr, sizeof(tempNode->Descr) - 1, "%s %s:(%d-%d) -> %s:(%d-%d)", tempNode->Protocol, tempNode->SrcIPStr, tempNode->SrcPortLower, tempNode->SrcPortUpper, tempNode->DstIPStr, tempNode->DstPortLower, tempNode->DstPortUpper);

    AddRuleToList(&gFwRulesList, tempNode);
    retVal++;
  }

END:

  if (fileHandle != NULL)
  {
    fclose(fileHandle);
  }

  return retVal;
}


int ParseDnsPoisoningConfigFile(char *configFileParam)
{
  int retVal = 0;
  FILE *fileHandle = NULL;
  char tmpLine[MAX_BUF_SIZE + 1];
  unsigned char hostname[MAX_BUF_SIZE + 1];
  unsigned char ttlStr[MAX_BUF_SIZE + 1];
  unsigned long ttlLong;
  unsigned char responseType[MAX_BUF_SIZE + 1];
  unsigned char spoofedIpAddr[MAX_BUF_SIZE + 1];
  unsigned char cnameHost[MAX_BUF_SIZE + 1];

  if (configFileParam == NULL)
  {
    goto END;
  }

  if (!PathFileExists(configFileParam))
  {
    goto END;
  }

  if ((fileHandle = fopen(configFileParam, "r")) == NULL)
  {
    goto END;
  }

  ZeroMemory(tmpLine, sizeof(tmpLine));
  ZeroMemory(hostname, sizeof(hostname));
  ZeroMemory(ttlStr, sizeof(ttlStr));
  ZeroMemory(spoofedIpAddr, sizeof(spoofedIpAddr));
  ZeroMemory(responseType, sizeof(responseType));
  ZeroMemory(cnameHost, sizeof(cnameHost));

  while (fgets(tmpLine, sizeof(tmpLine), fileHandle) != NULL)
  {
    // Remove trailing CR/LF
    while (tmpLine[strlen(tmpLine) - 1] == '\r' || 
           tmpLine[strlen(tmpLine) - 1] == '\n')
    {
      tmpLine[strlen(tmpLine) - 1] = '\0';
    }

    // Parse values and add them to the list.
    if (sscanf(tmpLine, "%[^,],%[^,],%[^,],%s", hostname, responseType, ttlStr, spoofedIpAddr) == 4)
    {
      ttlLong = atol(ttlStr);
      if (StrCmpI(responseType, "A") == 0)
      {
        AddSpoofedIpToList(&gDnsSpoofingList, hostname, ttlLong, spoofedIpAddr);        
      }
      else if (StrCmpI(responseType, "CNAME") == 0 &&
               StrChr(spoofedIpAddr, ',') != NULL)
      {
        strncpy(tmpLine, spoofedIpAddr, sizeof(tmpLine) - 1);
        sscanf(tmpLine, "%[^,],%s", cnameHost, spoofedIpAddr);
        AddSpoofedCnameToList(&gDnsSpoofingList, hostname, ttlLong, cnameHost, spoofedIpAddr);
      }

      retVal++;
    }

    ZeroMemory(tmpLine, sizeof(tmpLine));
    ZeroMemory(hostname, sizeof(hostname));
    ZeroMemory(spoofedIpAddr, sizeof(spoofedIpAddr));
    ZeroMemory(responseType, sizeof(responseType));
    ZeroMemory(cnameHost, sizeof(cnameHost));
  }

END:

  if (fileHandle != NULL)
  {
    fclose(fileHandle);
  }

  return retVal;
}

