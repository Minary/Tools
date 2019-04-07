#define HAVE_REMOTE

#include <pcap.h>
#include <Shlwapi.h>
#include <windows.h>

#include "Config.h"
#include "LinkedListTargetSystems.h"
#include "LinkedListFirewallRules.h"
#include "Logging.h"
#include "ModePcap.h"
#include "NetworkHelperFunctions.h"
#include "PacketHandlerIPv4Forwarding.h"
#include "RouterIPv4.h"


// GLobal/external variables
extern int gDEBUGLEVEL;
extern SCANPARAMS gScanParams;
extern PSYSNODE gTargetSystemsList;
extern pcap_t *gPcapHandle;


int InitializeParsePcapDumpFile()
{
  int funcRetVal;
  struct pcap_pkthdr *packetHeader = NULL;
  unsigned char *packetData = NULL;
  int retVal = -1;

  printf("InitializeParsePcapDumpFile(0): Starting\n");

  // Initialisation. Parse parameters (Ifc, start IP, stop IP) and
  // pack them in the scan configuration struct.
  MacBin2String(gScanParams.LocalMacBin, gScanParams.LocalMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.LocalIpBin, gScanParams.LocalIpStr, MAX_IP_LEN);

  MacBin2String(gScanParams.GatewayMacBin, gScanParams.GatewayMacStr, MAX_MAC_LEN);
  IpBin2String(gScanParams.GatewayIpBin, gScanParams.GatewayIpStr, MAX_IP_LEN);

  // Set exit function to trigger depoisoning functions and command.
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)RouterIPv4_ControlHandler, TRUE);

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

  LogMsg(DBG_INFO, "InitializeParsePcapDumpFile(1): -f interface=%s, pcapFile=%s",
    gScanParams.InterfaceName, gScanParams.PcapFilePath);

  // Open Pcap input file
  if (OpenPcapFileHandle(&gScanParams) == FALSE)
  {
    retVal = -1;
    goto END;
  }

  // Open Pcap interface read/write
  if (OpenPcapInterfaceHandle(&gScanParams) == FALSE)
  {
    retVal = -2;
    goto END;
  }

  // Start processing packets
  LogMsg(DBG_INFO, "CaptureIncomingPackets(): Pcap packet handling started ...");
  while ((funcRetVal = pcap_next_ex(gPcapHandle, (struct pcap_pkthdr **) &packetHeader, (const u_char **)&packetData)) >= 0)
  {
    if (funcRetVal == 1)
    {
      PacketForwarding_handler((unsigned char *)&gScanParams, packetHeader, packetData);
    }
  }

END:

  if (gPcapHandle != NULL)
  {
    pcap_close(gPcapHandle);
  }

  return retVal;
}



BOOL OpenPcapFileHandle(PSCANPARAMS scanParams)
{
  BOOL retVal = FALSE;
  char errbuf[PCAP_ERRBUF_SIZE];

  if ((gPcapHandle = pcap_open_offline(gScanParams.PcapFilePath, errbuf)) == NULL)
  {
    fprintf(stderr, "Unable to open the file %s.\nerror=%s\n", gScanParams.PcapFilePath, errbuf);
    retVal = FALSE;
  }
  else
  {
    retVal = TRUE;
  }

  return retVal;
}



BOOL OpenPcapInterfaceHandle(PSCANPARAMS scanParams)
{
  BOOL retVal = FALSE;
  struct bpf_program ifcCode;
  char pcapErrorBuffer[PCAP_ERRBUF_SIZE];
  char filter[MAX_BUF_SIZE + 1];
  unsigned int netMask = 0;
  char adapter[MAX_BUF_SIZE + 1];
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  int counter;

  ZeroMemory(pcapErrorBuffer, sizeof(pcapErrorBuffer));

  // Open interface.
  if ((scanParams->InterfaceReadHandle = pcap_open_live((char *)scanParams->InterfaceName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS, PCAP_READTIMEOUT, pcapErrorBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "OpenPcapInterfaceHandle(): Unable to open the adapter");
    retVal = FALSE;
    goto END;
  }

  // Open device list.
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, pcapErrorBuffer) == -1)
  {
    retVal = FALSE;
    goto END;
  }

  ZeroMemory(adapter, sizeof(adapter));
  for (counter = 0, device = allDevices; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, (LPCSTR)scanParams->InterfaceName))
    {
      strcpy(adapter, device->name);
      break;
    }
  }

  // MAC == LocalMAC and (IP == GWIP or IP == VictimIP
  scanParams->InterfaceWriteHandle = scanParams->InterfaceReadHandle;
  ZeroMemory(&ifcCode, sizeof(ifcCode));
  ZeroMemory(filter, sizeof(filter));

  _snprintf(filter, sizeof(filter) - 1, "ip && ether dst %s && not src host %s && not dst host %s", scanParams->LocalMacStr, scanParams->LocalIpStr, scanParams->LocalIpStr);
  netMask = 0xffffff; // "255.255.255.0"

  if (pcap_compile((pcap_t *)scanParams->InterfaceWriteHandle, &ifcCode, (const char *)filter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "OpenPcapInterfaceHandle(): Unable to compile the BPF filter \"%s\"", filter);
    retVal = FALSE;
    goto END;
  }

  if (pcap_setfilter((pcap_t *)scanParams->InterfaceWriteHandle, &ifcCode) < 0)
  {
    LogMsg(DBG_ERROR, "OpenPcapInterfaceHandle(): Unable to set the BPF filter \"%s\"", filter);
    retVal = FALSE;
    goto END;
  }

  // Everything went well so far.
  // Set the return value to true.
  retVal = TRUE;
END:

  return retVal;
}
