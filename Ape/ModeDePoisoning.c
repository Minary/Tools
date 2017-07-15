#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <Shlwapi.h>
#include <stdio.h>

#include "APE.h"
#include "LinkedListSystems.h"
#include "Logging.h"
#include "ModeDePoisoning.h"


extern int gDEBUGLEVEL;
extern SCANPARAMS gScanParams;
extern PSYSNODE gSystemsList;
extern char **gARGV;


void InitializeDePoisoning()
{
  AdminCheck(gScanParams.applicationName);
  if (gDEBUGLEVEL > DBG_INFO)
  {
    PrintConfig(gScanParams);
  }

  ArpDePoisoning(&gScanParams);
  RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
  Sleep(500);
  RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
}


void StartUnpoisoningProcess()
{
  char tempBuffer[MAX_BUF_SIZE + 1];
  char gatewayIpStr[MAX_BUF_SIZE + 1];

  // Start unpoison process.
  ZeroMemory(tempBuffer, sizeof(tempBuffer));
  snprintf(tempBuffer, sizeof(tempBuffer) - 1, "\"%s\" -d %s", gARGV[0], gARGV[2]);
  LogMsg(DBG_INFO, "StartUnpoisoningProcess(): Starting Depoison child process");
  ExecCommand(tempBuffer);

  // Remove GW ARP entry.
  ZeroMemory(tempBuffer, sizeof(tempBuffer));
  ZeroMemory(gatewayIpStr, sizeof(gatewayIpStr));
  snprintf(gatewayIpStr, sizeof(gatewayIpStr) - 1, "%d.%d.%d.%d", gScanParams.gatewayIpBin[0], gScanParams.gatewayIpBin[1], gScanParams.gatewayIpBin[2], gScanParams.gatewayIpBin[3]);
  RemoveMacFromCache((char *)gScanParams.interfaceAlias, gatewayIpStr);
}



void WriteDepoisoningFile(void)
{
  int counter = 0;
  int numberSystems = 0;
  SYSTEMNODE systemList[MAX_SYSTEMS_COUNT];
  FILE *fileHandle = NULL;
  char tempBuffer[MAX_BUF_SIZE + 1];
  char srcMacStr[MAX_BUF_SIZE + 1];
  PSYSNODE systemListPtr = gSystemsList;


  // Get a copy of all systems found in the network.
  while (systemListPtr != NULL)
  {
    ZeroMemory(srcMacStr, sizeof(srcMacStr));
    MacBin2String(systemListPtr->data.sysMacBin, (unsigned char *)srcMacStr, sizeof(srcMacStr));
    LogMsg(DBG_INFO, "WriteDepoisoningFile(): %s/%s", systemListPtr->data.sysIpStr, srcMacStr);

    if (strnlen((char *)systemListPtr->data.sysIpStr, MAX_IP_LEN) > 0)
    {
      CopyMemory(systemList[numberSystems].sysIpStr, systemListPtr->data.sysIpStr, MAX_IP_LEN);
      CopyMemory(systemList[numberSystems].sysMacBin, systemListPtr->data.sysMacBin, BIN_MAC_LEN);
      numberSystems++;
    }

    systemListPtr = systemListPtr->next;
  }

  // Depoison the victim systems
  if (numberSystems <= 0)
  {
    return;
  }

  LogMsg(DBG_INFO, "WriteDepoisoningFile(): Depoison  %d systems", numberSystems);
  if ((fileHandle = fopen(FILE_UNPOISON, "w")) == NULL)
  {
    return;
  }
  counter = 0;

  while (counter < numberSystems && counter < MAX_SYSTEMS_COUNT)
  {
    if (systemList[counter].sysIpStr != NULL && 
        strnlen((char *)systemList[counter].sysIpStr, MAX_IP_LEN) > 0 &&
        systemList[counter].sysMacBin != NULL)
    {
      ZeroMemory(tempBuffer, sizeof(tempBuffer));
      snprintf(tempBuffer, sizeof(tempBuffer) - 1, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", systemList[counter].sysMacBin[0], systemList[counter].sysMacBin[1],
        systemList[counter].sysMacBin[2], systemList[counter].sysMacBin[3], systemList[counter].sysMacBin[4], systemList[counter].sysMacBin[5]);

      fprintf(fileHandle, "%s,%s\n", systemList[counter].sysIpStr, tempBuffer);
    }

    counter++;
  }

  fclose(fileHandle);
}


void ExecCommand(char *commandParam)
{
  STARTUPINFO startupInfo;
  PROCESS_INFORMATION processInfo;
  char tempBuffer[MAX_BUF_SIZE + 1];
  char *comspec = getenv("COMSPEC");

  // Build command string + execute it.
  if (commandParam != NULL)
  {
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    ZeroMemory(tempBuffer, sizeof(tempBuffer));

    comspec = comspec != NULL ? comspec : "cmd.exe";
    startupInfo.cb = sizeof(STARTUPINFO);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    snprintf(tempBuffer, sizeof(tempBuffer) - 1, "%s /c %s", comspec, commandParam);
    LogMsg(DBG_INFO, "ExecCommand(): %s", tempBuffer);
    CreateProcess(NULL, tempBuffer, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInfo);
  }
}



DWORD WINAPI ArpDePoisoning(LPVOID scanParamsParam)
{
  int retVal = 0;
  ArpPacket arpPacket;
  PSCANPARAMS lTmpParams = (PSCANPARAMS)scanParamsParam;
  SCANPARAMS scanParams;
  unsigned char remoteIpString[MAX_IP_LEN + 1];
  FILE *fileHandle = NULL;
  char tempFleLine[MAX_BUF_SIZE + 1];

  unsigned char remoteMacBin[BIN_MAC_LEN];
  unsigned int remoteIpBin[BIN_IP_LEN];
  unsigned char remoteMacStr[MAX_MAC_LEN + 1];
  unsigned int arpBroadcast[BIN_MAC_LEN];
  int counter = 0;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  pcap_t *interfaceHandle = NULL;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  char adapter[MAX_BUF_SIZE + 1];
  int i = 0;

  LogMsg(DBG_LOW, "ArpDePoisoning(): Starting");
  ZeroMemory(&scanParams, sizeof(scanParams));
  CopyMemory(&scanParams, lTmpParams, sizeof(scanParams));
  memset(arpBroadcast, 255, BIN_MAC_LEN);

  // Open device list.
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, tempBuffer) == -1)
  {
    retVal = 1;
    goto END;
  }

  ZeroMemory(adapter, sizeof(adapter));

  for (counter = 0, device = allDevices; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, (LPCSTR)scanParams.interfaceName))
    {
      strcpy(adapter, device->name);
      break;
    }
  }

  // Open interface.
  if ((interfaceHandle = pcap_open(adapter, 65536, (int)NULL, PCAP_READTIMEOUT, NULL, tempBuffer)) == NULL)
  {
    retVal = -2;
    goto END;
  }

  if ((fileHandle = fopen(FILE_UNPOISON, "r")) == NULL)
  {
    retVal = -3;
    goto END;
  }

  while (fgets(tempFleLine, sizeof(tempFleLine) - 1, fileHandle) != NULL)
  {
    while (tempFleLine[strlen(tempFleLine) - 1] == '\r' || tempFleLine[strlen(tempFleLine) - 1] == '\n')
    {
      tempFleLine[strlen(tempFleLine) - 1] = '\0';
    }

    ZeroMemory(remoteIpString, sizeof(remoteIpString));
    ZeroMemory(remoteMacStr, sizeof(remoteMacStr));
    ZeroMemory(&arpPacket, sizeof(arpPacket));
    ZeroMemory(remoteMacBin, BIN_MAC_LEN);
    ZeroMemory(remoteIpBin, BIN_IP_LEN);

    if (strchr(tempFleLine, ',') == NULL)
    {
      continue;
    }

    if (sscanf((char *)tempFleLine, "%[^,],%s", remoteIpString, remoteMacStr) == 2 && strlen((char *)remoteIpString) > 0 && strlen((char *)remoteMacStr) <= 0)
    {
      continue;
    }

    MacString2Bin(remoteMacBin, remoteMacStr, MAX_MAC_LEN);
    IpString2Bin((char *)remoteIpBin, remoteIpString, MAX_IP_LEN);

    // Initialisation
    ZeroMemory(&arpPacket, sizeof(arpPacket));
    arpPacket.lReqType = ARP_REQUEST;
    // Set MAC values
    CopyMemory(arpPacket.EthSrcMacBin, scanParams.localMacBin, BIN_MAC_LEN);
    CopyMemory(arpPacket.EthDstMacBin, remoteMacBin, BIN_MAC_LEN);

    // Set ARP reply values
    CopyMemory(arpPacket.ArpLocalMacBin, scanParams.gatewayMacBin, BIN_MAC_LEN);
    CopyMemory(arpPacket.ArpLocalIpBin, scanParams.gatewayIpBin, BIN_IP_LEN);
    CopyMemory(arpPacket.ArpDstIpBin, remoteIpBin, BIN_IP_LEN);

    // layer 2 : (Attacker-MAC) 00-16-ea-e0-77-b2    ->   (GW-MAC) 00-40-77-bb-55-10
    // layer 3 : (Victim-MAC) 00-1b-77-53-5c-f8/192.168.100.117    ->   00-00-00-00-00-00/192.168.100.1
    LogMsg(DBG_INFO, "ArpDepoisoning(): %s/%s", remoteIpString, remoteMacStr);
    LogMsg(DBG_INFO, "ArpDepoisoning(): %d.%d.%d.%d/%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX",
      remoteIpString, remoteMacStr);

    // Send 3 ARP depoisoning packets.
    for (i = 0; i < 3; i++)
    {
      if (SendArpPacket(interfaceHandle, &arpPacket) != 0)
      {
        LogMsg(DBG_ERROR, "ArpDepoisoning(): Unable to send ARP packet.");
      }

      Sleep(SLEEP_BETWEEN_ARPS);
    }

    RemoveMacFromCache((char *)scanParams.interfaceAlias, (char *)remoteIpString);
    Sleep(SLEEP_BETWEEN_ARPS);
  }


END:

  if (fileHandle != NULL)
  {
    fclose(fileHandle);
  }

  if (interfaceHandle)
  {
    pcap_close(interfaceHandle);
  }

  LogMsg(DBG_LOW, "ArpDepoisoning(): exit");

  return retVal;
}
