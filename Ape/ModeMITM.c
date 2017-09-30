#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#include "APE.h"
#include "ArpPoisoning.h"
#include "DnsPoisoning.h"
#include "LinkedListTargetSystems.h"
#include "LinkedListFirewallRules.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "Logging.h"
#include "NetworkHelperFunctions.h"
#include "PacketProxy.h"


extern int gDEBUGLEVEL;
extern RULENODE gFwRulesList;
extern PSYSNODE gTargetSystemsList;
extern PHOSTNODE gDnsSpoofingList;
extern SCANPARAMS gScanParams;

DWORD gRESENDThreadID = 0;
DWORD gPOISONINGThreadID = 0;

HANDLE gRESENDThreadHandle = INVALID_HANDLE_VALUE;
HANDLE gPOISONINGThreadHandle = INVALID_HANDLE_VALUE;

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
  AdminCheck(gScanParams.ApplicationName);
  RemoveMacFromCache((char *)gScanParams.InterfaceName, "*");
  Sleep(500);
  RemoveMacFromCache((char *)gScanParams.InterfaceName, "*");
  LogMsg(2, "InitializeMITM(): -x %s\n", gScanParams.InterfaceName);
  
  // Initialisation. Parse parameters (Ifc, start IP, stop IP) and
  // pack them in the scan configuration struct.
  MacBin2String(gScanParams.LocalMacBin, gScanParams.LocalMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.LocalIpBin, gScanParams.LocalIpStr, MAX_IP_LEN);

  MacBin2String(gScanParams.GatewayMacBin, gScanParams.GatewayMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.GatewayIpBin, gScanParams.GatewayIpStr, MAX_IP_LEN);

  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)APE_ControlHandler, TRUE);

  // Set GW IP static.
  SetMacStatic((char *)gScanParams.InterfaceAlias, (char *)gScanParams.GatewayIpStr, (char *)gScanParams.GatewayMacStr);

  if (gDEBUGLEVEL > DBG_INFO)
  {
    PrintConfig(gScanParams);
  }

  // 0 Add default GW to the gSystemsList
  AddToSystemsList(&gTargetSystemsList, gScanParams.GatewayMacBin, (char *)gScanParams.GatewayIpStr, gScanParams.GatewayIpBin);
  
  // 1. Parse target file
  if (!PathFileExists(FILE_HOST_TARGETS))
  {
    printf(stderr, "No target hosts file \"%s\"!\n", FILE_HOST_TARGETS);
    goto END;
  }

  if (ParseTargetHostsConfigFile(FILE_HOST_TARGETS) <= 0)
  {
    fprintf(stderr, "No target hosts were defined!\n");
    goto END;
  }
  
  PrintDnsSpoofingRulesNodes(gDnsSpoofingList);
  PrintTargetSystems(gTargetSystemsList);

  WriteDepoisoningFile();


  // 1. Start Ethernet FORWARDING thread
  if ((gRESENDThreadHandle = CreateThread(NULL, 0, ForwardPackets, &gScanParams, 0, &gRESENDThreadID)) == NULL ||
       gRESENDThreadHandle == INVALID_HANDLE_VALUE)
  {
    LogMsg(DBG_ERROR, "main(): Can't start Listener thread : %d", GetLastError());
    goto END;
  }

  // 2. Start POISONING the ARP caches.
  if ((gPOISONINGThreadHandle = CreateThread(NULL, 0, ArpPoisoningLoop, &gScanParams, 0, &gPOISONINGThreadID)) == NULL ||
       gPOISONINGThreadHandle == INVALID_HANDLE_VALUE)
  {
    LogMsg(DBG_ERROR, "main(): Can't start NetworkScanner thread : %d", GetLastError());
    goto END;
  }

printf("gPOISONINGThreadHandle=%d, gRESENDThreadHandle=%d, INVALID_HANDLE_VALUE=%d\n",
  gPOISONINGThreadHandle, gRESENDThreadHandle, INVALID_HANDLE_VALUE);

  //Sleep(500);
  DWORD la = 111;
  //while (gPOISONINGThreadHandle != INVALID_HANDLE_VALUE && 
  //       gRESENDThreadHandle != INVALID_HANDLE_VALUE)
  while(1 == 1)
  {
    if ((la = WaitForSingleObject(gPOISONINGThreadHandle, 30)) != WAIT_TIMEOUT &&
         la != WAIT_OBJECT_0)
    {
printf("gPOISONINGThreadHandle: la=%d (WAIT_ABANDONED=%d), WAIT_OBJECT_0=%d, WAIT_TIMEOUT=%d, WAIT_FAILED=%d\n", 
  la, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED);

if (la == WAIT_FAILED)
{
  printf("gPOISONINGThreadHandle: ErrorCode=%d\n", GetLastError());
}
      LogMsg(DBG_ERROR, "main(): ARP poisoning thread stopped");
      break;
    }

    if ((la = WaitForSingleObject(gRESENDThreadHandle, 30)) != WAIT_TIMEOUT &&
        la != WAIT_OBJECT_0)
    {
printf("gRESENDThreadHandle: la=%d (WAIT_ABANDONED=%d), WAIT_OBJECT_0=%d, WAIT_TIMEOUT=%d, WAIT_FAILED=%d\n", 
  la, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED);

if (la == WAIT_FAILED)
{
  printf("gRESENDThreadHandle: ErrorCode=%d\n", GetLastError());
}

      LogMsg(DBG_ERROR, "main(): Packet forarder thread was stopped");
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
    fprintf(stderr, "\nAPE (ARP Poisoning Engine)  Version %s\n", APE_VERSION);
    fprintf(stderr, "---------------------------------------\n\n");
    fprintf(stderr, "Web\t https://github.com/rubenunteregger\n\n\n");
    fprintf(stderr, "You need Administrator permissions to run %s successfully!\n\n", programNameParam);

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
    {
      retVal = FALSE;
    }

    FreeSid(admGroup);
  }

  return retVal;
}
