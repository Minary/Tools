#include <stdio.h>
#include <Shlwapi.h>

#include "LinkedListSpoofedDnsHosts.h"
#include "LinkedListTargetSystems.h"
#include "Logging.h"
#include "NetworkHelperFunctions.h"


// External/Global variables
extern PHOSTNODE gDnsSpoofingList;
extern PSYSNODE gTargetSystemsList;



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
    while (tempLine[strlen(tempLine) - 1] == '\r' || 
           tempLine[strlen(tempLine) - 1] == '\n')
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
  unsigned char cwd[MAX_BUF_SIZE + 1];


  if (configFileParam == NULL)
  {
    goto END;
  }

  ZeroMemory(cwd, sizeof(cwd));
  GetCurrentDirectory(sizeof(cwd) - 1, cwd);

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
