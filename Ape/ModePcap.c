#define HAVE_REMOTE

#include <pcap.h>
#include <Shlwapi.h>
#include <windows.h>

#include "APE.h"
#include "Logging.h"


extern SCANPARAMS gScanParams;


void InitializeParsePcapDumpFile()
{
  char filter[MAX_BUF_SIZE + 1];
  unsigned int netMask = 0;
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i;
  int counter = 0;
  struct bpf_program ifcCode;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *dumpfile;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  pcap_t *interfaceHandle = NULL;
  int retVal = -1;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  char adapter[MAX_BUF_SIZE + 1];
  SCANPARAMS scanParams;

  printf("InitializeParsePcapDumpFile(): Starting\n");
  ZeroMemory(&scanParams, sizeof(scanParams));
  CopyMemory(&scanParams, &gScanParams, sizeof(scanParams));

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


  /* Jump to the selected adapter */
  for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);


  /* Open the device */
  if ((adhandle = pcap_open(d->name,          // name of the device
    65536,            // portion of the packet to capture
                      // 65536 guarantees that the whole packet will be captured on all the link layers
    PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
    1000,             // read timeout
    NULL,             // authentication on the remote machine
    errbuf            // error buffer
  )) == NULL)
  {
    fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -3;
  }

  // Open the dump file 
  if ((dumpfile = pcap_dump_open(adhandle, scanParams.PcapFilePath)) == NULL)
  {
    fprintf(stderr, "\nError opening output file\n");
    return -4;
  }

  printf("Listening on %s... Press Ctrl+C to stop...\n", d->description);

  // At this point, we no longer need the device list. Free it 
  pcap_freealldevs(alldevs);


  // MAC == LocalMAC and (IP == GWIP or IP == VictimIP
  scanParams.interfaceWriteHandle = scanParams.interfaceReadHandle;
  ZeroMemory(&ifcCode, sizeof(ifcCode));
  ZeroMemory(filter, sizeof(filter));

  _snprintf(filter, sizeof(filter) - 1, "ip && ether dst %s && not src host %s && not dst host %s", scanParams.localMacStr, scanParams.localIpStr, scanParams.localIpStr);
  netMask = 0xffffff; // "255.255.255.0"

  if (pcap_compile((pcap_t *)scanParams.interfaceWriteHandle, &ifcCode, (const char *)filter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "CaptureIncomingPackets(): Unable to compile the BPF filter \"%s\"", filter);
    retVal = 6;
    goto END;
  }

  if (pcap_setfilter((pcap_t *)scanParams.interfaceWriteHandle, &ifcCode) < 0)
  {
    LogMsg(DBG_ERROR, "CaptureIncomingPackets(): Unable to set the BPF filter \"%s\"", filter);
    retVal = 7;
    goto END;
  }


END:

  return retVal;
}



