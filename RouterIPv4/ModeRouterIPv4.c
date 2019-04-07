#define HAVE_REMOTE

#include <pcap.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <Windows.h>

#include "Config.h"
#include "LinkedListTargetSystems.h"
#include "LinkedListFirewallRules.h"
#include "Logging.h"
#include "ModeRouterIPv4.h"
#include "NetworkHelperFunctions.h"
#include "PacketHandlerIPv4Forwarding.h"
#include "RouterIPv4.h"

// Global variables
extern int gDEBUGLEVEL;
extern RULENODE gFwRulesList;
extern PSYSNODE gTargetSystemsList;
extern SCANPARAMS gScanParams;

DWORD gRESENDThreadID = 0;
HANDLE gRESENDThreadHandle = INVALID_HANDLE_VALUE;


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


void InitializeRouterIPv4()
{
  AdminCheck(gScanParams.ApplicationName);
  LogMsg(2, "InitializeArpMitm(): -x %s", gScanParams.InterfaceName);

  // Initialisation. Parse parameters (Ifc, start IP, stop IP) and
  // pack them in the scan configuration struct.
  MacBin2String(gScanParams.LocalMacBin, gScanParams.LocalMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.LocalIpBin, gScanParams.LocalIpStr, MAX_IP_LEN);
  MacBin2String(gScanParams.GatewayMacBin, gScanParams.GatewayMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.GatewayIpBin, gScanParams.GatewayIpStr, MAX_IP_LEN);

  if (gDEBUGLEVEL > DBG_INFO)
  {
    PrintConfig(gScanParams);
  }

  // 0 Add default GW to the gSystemsList
  AddToSystemsList(&gTargetSystemsList, gScanParams.GatewayMacBin, (char *)gScanParams.GatewayIpStr, gScanParams.GatewayIpBin);

  // 1. Parse target file
  if (PathFileExists(FILE_HOST_TARGETS) &&
      ParseTargetHostsConfigFile(FILE_HOST_TARGETS) <= 0)
  {
    LogMsg(DBG_ERROR, "InitializeRouterIPv4(): No target hosts were defined");
    Sleep(1000);
    goto END;
  }
  else
  {
    LogMsg(DBG_ERROR, "InitializeRouterIPv4(): No target hosts file \"%s\"", FILE_HOST_TARGETS);
  }

  PrintTargetSystems(gTargetSystemsList);

  // 1. Start IPv4 router
  PacketHandlerRouterIPv4(&gScanParams);

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
    fprintf(stderr, "\nRouterIPv4 Version %s\n", ROUTERIPV4_VERSION);
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



