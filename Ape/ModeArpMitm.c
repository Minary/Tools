#define HAVE_REMOTE

#include <pcap.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
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
  ParseTargetHostsConfigFile(FILE_HOST_TARGETS);
  RemoveMacFromCache((char *)gScanParams.InterfaceName, "*");
  Sleep(500);
  RemoveMacFromCache((char *)gScanParams.InterfaceName, "*");
  LogMsg(DBG_INFO, "InitializeArpMitm(): -x %s", gScanParams.InterfaceName);  

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

  // Add default GW to the gSystemsList
  AddToSystemsList(&gTargetSystemsList, gScanParams.GatewayMacBin, (char *)gScanParams.GatewayIpStr, gScanParams.GatewayIpBin);  
  PrintTargetSystems(gTargetSystemsList);
  WriteDepoisoningFile();

  // Start targethosts observer file
  if (InitTargethostObserverThread() == FALSE)
  {
    LogMsg(DBG_INFO, "InitializeArpMitm(): Could not start .targethosts observer thread");
    return;
  }

  // Start POISONING the ARP caches.
  ArpPoisoningLoop(&gScanParams);

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
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.PcapFileHandle");
    pcap_breakloop(gScanParams.PcapFileHandle);
    pcap_close(gScanParams.PcapFileHandle);
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.PcapFileHandle done");
  }

  if (gScanParams.InterfaceWriteHandle != NULL)
  {
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceWriteHandle");
    pcap_breakloop(gScanParams.InterfaceWriteHandle);
    pcap_close(gScanParams.InterfaceWriteHandle);
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceWriteHandle done");
  }

  if (gScanParams.InterfaceReadHandle != NULL)
  {
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceReadHandle");
    pcap_breakloop(gScanParams.InterfaceReadHandle);
    pcap_close(gScanParams.InterfaceReadHandle);
    LogMsg(DBG_INFO, "CloseAllPcapHandles(): Closing gScanParams.InterfaceReadHandle done");
  }
}


BOOL InitTargethostObserverThread()
{
  HANDLE threadHandle = INVALID_HANDLE_VALUE;
  DWORD dwThreadId = -1;

  if ((threadHandle = CreateThread(NULL, 0, TargethostsObserver, NULL, 0, &dwThreadId)) == NULL)
  {
    return FALSE;
  }

  return TRUE;
}


DWORD WINAPI TargethostsObserver(LPVOID params)
{
  struct _stat statbuf;
  time_t mtime_previous;
  int stat = _stat(FILE_HOST_TARGETS, &statbuf);

  while (1 == 1)
  {
    mtime_previous = statbuf.st_mtime;
    stat = _stat(FILE_HOST_TARGETS, &statbuf);

    if (mtime_previous != statbuf.st_mtime)
    {
      LogMsg(DBG_INFO, "TargethostsObserver(): .targethosts changed. Reloading .targethost records.");
      ClearSystemList(&gTargetSystemsList);
      ParseTargetHostsConfigFile(FILE_HOST_TARGETS);
      PrintTargetSystems(FILE_HOST_TARGETS);
    }

    Sleep(1000);
  }
}
