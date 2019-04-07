#define HAVE_REMOTE

#include <pcap.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <Windows.h>

#include "APE.h"
#include "ArpPoisoning.h"
#include "LinkedListTargetSystems.h"
#include "LinkedListFirewallRules.h"
#include "Logging.h"
#include "ModeArpMitm.h"
#include "NetworkHelperFunctions.h"


// External/global variables
extern int gDEBUGLEVEL;
extern RULENODE gFwRulesList;
extern PSYSNODE gTargetSystemsList;
extern SCANPARAMS gScanParams;

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

void InitializeArpMitm()
{
  AdminCheck(gScanParams.ApplicationName);
  RemoveMacFromCache((char *)gScanParams.InterfaceName, "*");
  Sleep(500);
  RemoveMacFromCache((char *)gScanParams.InterfaceName, "*");
  LogMsg(2, "InitializeArpMitm(): -x %s\n", gScanParams.InterfaceName);  

  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)APE_ControlHandler, TRUE);

  // Initialisation. Parse parameters (Ifc, start IP, stop IP) and
  // pack them in the scan configuration struct.
  MacBin2String(gScanParams.LocalMacBin, gScanParams.LocalMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.LocalIpBin, gScanParams.LocalIpStr, MAX_IP_LEN);
  MacBin2String(gScanParams.GatewayMacBin, gScanParams.GatewayMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.GatewayIpBin, gScanParams.GatewayIpStr, MAX_IP_LEN);

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
    fprintf(stderr, "No target hosts file \"%s\"!\n", FILE_HOST_TARGETS);
    goto END;
  }

  if (ParseTargetHostsConfigFile(FILE_HOST_TARGETS) <= 0)
  {
    fprintf(stderr, "No target hosts were defined!\n");
    goto END;
  }

  PrintTargetSystems(gTargetSystemsList);
  WriteDepoisoningFile();

  // 2. Start POISONING the ARP caches.
  ArpPoisoningLoop(&gScanParams);

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



BOOL APE_ControlHandler(DWORD pControlType)
{
  switch (pControlType)
  {
    // Handle the CTRL-C signal. 
  case CTRL_C_EVENT:
    LogMsg(DBG_INFO, "Ctrl-C event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-C event : pcap closed");
    StartUnpoisoningProcess();
    return FALSE;

  case CTRL_CLOSE_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Close event : Starting depoisoning process");
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Close event : pcap closed");
    return FALSE;

  case CTRL_BREAK_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Break event : Starting depoisoning process");
    StartUnpoisoningProcess();
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Break event : pcap closed");
    return FALSE;

  case CTRL_LOGOFF_EVENT:
    printf("Ctrl-Logoff event : Starting depoisoning process");
    StartUnpoisoningProcess();
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-Logoff event : pcap closed");
    return FALSE;

  case CTRL_SHUTDOWN_EVENT:
    LogMsg(DBG_INFO, "Ctrl-Shutdown event : Starting depoisoning process");
    StartUnpoisoningProcess();
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Ctrl-SHutdown event : pcap closed");
    return FALSE;

  default:
    LogMsg(DBG_INFO, "Unknown event \"%d\" : Starting depoisoning process", pControlType);
    StartUnpoisoningProcess();
    CloseAllPcapHandles();
    LogMsg(DBG_INFO, "Unknown event : pcap closed");
    return FALSE;
  }
}


void CloseAllPcapHandles()
{
  if (gScanParams.PcapFileHandle != NULL)
  {
    pcap_breakloop(gScanParams.PcapFileHandle);
  }

  if (gScanParams.InterfaceWriteHandle != NULL)
  {
    pcap_breakloop(gScanParams.InterfaceWriteHandle);
  }

  if (gScanParams.InterfaceReadHandle != NULL)
  {
    pcap_breakloop(gScanParams.InterfaceReadHandle);
  }
}
