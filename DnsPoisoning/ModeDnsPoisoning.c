#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#include "PacketHandlerDP.h"
#include "Config.h"
#include "DnsPoisoning.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "LinkedListTargetSystems.h"
#include "Logging.h"
#include "ModeDnsPoisoning.h"
#include "NetworkHelperFunctions.h"


extern int gDEBUGLEVEL;
extern SCANPARAMS gScanParams;
extern PSYSNODE gTargetSystemsList;

DWORD gPOISONINGThreadID = 0;
HANDLE gPOISONINGThreadHandle = INVALID_HANDLE_VALUE;

/*
 * All-in-one solution, target range
 *
 * param   Ifc-Name
 *   -x     {...}
 *
 * 1. Parse input DNS poisoning list
 * 2. StartDnsPoisoning thread
 *
 */


void InitializeDP()
{
  AdminCheck(gScanParams.ApplicationName);
  LogMsg(2, "InitializeDP(): -x %s", gScanParams.InterfaceName);

  // Initialisation. Parse parameters (Ifc, start IP, stop IP) and
  // pack them in the scan configuration struct.
  MacBin2String(gScanParams.LocalMacBin, gScanParams.LocalMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.LocalIpBin, gScanParams.LocalIpStr, MAX_IP_LEN);
  MacBin2String(gScanParams.GatewayMacBin, gScanParams.GatewayMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.GatewayIpBin, gScanParams.GatewayIpStr, MAX_IP_LEN);

  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)DP_ControlHandler, TRUE);

  if (gDEBUGLEVEL > DBG_INFO)
  {
    PrintConfig(gScanParams);
  }

  // 1. Parse target file
  if (!PathFileExists(FILE_HOST_TARGETS))
  {
    printf("No target hosts file \"%s\"!\n", FILE_HOST_TARGETS);
  }

  if (ParseTargetHostsConfigFile(FILE_HOST_TARGETS) <= 0)
  {
    printf("No target hosts were defined!\n");
  }

  PrintTargetSystems(gTargetSystemsList);


  // 1. Start Ethernet FORWARDING thread
  if ((gPOISONINGThreadHandle = CreateThread(NULL, 0, PacketHandlerDP, &gScanParams, 0, &gPOISONINGThreadID)) == NULL ||
      gPOISONINGThreadHandle == INVALID_HANDLE_VALUE)
  {
    LogMsg(DBG_ERROR, "InitializeDP(): Can't start Listener thread : %d", GetLastError());
    goto END;
  }

  DWORD waitStatus = 0;
  while (gPOISONINGThreadHandle != INVALID_HANDLE_VALUE)
  {
    if ((waitStatus = WaitForSingleObject(gPOISONINGThreadHandle, 30)) != WAIT_TIMEOUT &&
        waitStatus != WAIT_OBJECT_0)
    {
      LogMsg(DBG_ERROR, "InitializeDP(): DNS poisoning thread stopped");
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
    fprintf(stderr, "\nDNS Poisoning version %s\n", DNSPOISONING_VERSION);
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
