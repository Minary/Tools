#define HAVE_REMOTE

#include <pcap.h>
#include <Shlwapi.h>
#include <windows.h>

#include "APE.h"
#include "Packets.h"
#include "NetworkFunctions.h"


/*
*
*
*/
DWORD WINAPI ArpDePoisoning(LPVOID scanParamsParam)
{
  int retVal = 0;
  ArpPacket arpPacket;
  PSCANPARAMS lTmpParams = (PSCANPARAMS) scanParamsParam;
  SCANPARAMS scanParams;
  unsigned char remoteIpString[MAX_IP_LEN + 1];
  FILE *fileHandle = NULL;
  char tempFleLine[MAX_BUF_SIZE + 1];


  unsigned int remoteMacBin[BIN_MAC_LEN];
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


  LogMsg(DBG_LOW, "ArpDePoisoning() : Starting");

  ZeroMemory(&scanParams, sizeof(scanParams));
  CopyMemory(&scanParams, lTmpParams, sizeof(scanParams));
  memset(arpBroadcast, 255, BIN_MAC_LEN);


  // Open device list.
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, tempBuffer) != -1)
  {
    ZeroMemory(adapter, sizeof(adapter));

    for (counter = 0, device = allDevices; device; device = device->next, counter++)
    {
      if (StrStrI(device->name, (LPCSTR) scanParams.interfaceName))
      {
        strcpy(adapter, device->name);
        break;
      }
    }

    // Open interface.
    if ((interfaceHandle = pcap_open(adapter, 65536, (int) NULL, PCAP_READTIMEOUT, NULL, tempBuffer)) != NULL)
    {
      if ((fileHandle = fopen(FILE_UNPOISON, "r")) != NULL)		
      {
        while (fgets(tempFleLine, sizeof(tempFleLine) - 1, fileHandle) != NULL)
        {
          while (tempFleLine[strlen(tempFleLine)-1] == '\r' || tempFleLine[strlen(tempFleLine)-1] == '\n') 
            tempFleLine[strlen(tempFleLine)-1] = '\0';

          ZeroMemory(remoteIpString, sizeof(remoteIpString));
          ZeroMemory(remoteMacStr, sizeof(remoteMacStr));
          ZeroMemory(&arpPacket, sizeof(arpPacket));
          ZeroMemory(remoteMacBin, BIN_MAC_LEN);
          ZeroMemory(remoteIpBin, BIN_IP_LEN);


          if (strchr(tempFleLine, ',') != NULL)
          {
            if (sscanf((char *) tempFleLine, "%[^,],%s", remoteIpString, remoteMacStr) == 2 && strlen((char *) remoteIpString) > 0 && strlen((char *) remoteMacStr) > 0)
            {
              MacString2Bin(remoteMacBin, remoteMacStr,  MAX_MAC_LEN);
              IpString2Bin(remoteIpBin, remoteIpString, MAX_IP_LEN);

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

			  LogMsg(DBG_INFO, "ArpDepoisoning() : %s/%s", remoteIpString, remoteMacStr);
			  LogMsg(DBG_INFO, "ArpDepoisoning() : %d.%d.%d.%d/%02x-%02x-%02x-%02x-%02x-%02x", 
				  remoteIpString, remoteMacStr);
              /*
              * Send 3 ARP depoisoning packets.
              */
              for (i = 0; i < 3; i++)
              {
                if (SendArpPacket(interfaceHandle, &arpPacket) != 0)
                  LogMsg(DBG_ERROR, "ArpDepoisoning() : Unable to send ARP packet.");

                Sleep(SLEEP_BETWEEN_ARPS);
              } 

              RemoveMacFromCache((char *) scanParams.interfaceAlias, (char *) remoteIpString);
              Sleep(SLEEP_BETWEEN_ARPS); 
            }
          }
        }

        fclose(fileHandle);
      }

      if (interfaceHandle)
        pcap_close(interfaceHandle);
    }
  }

  LogMsg(DBG_LOW, "ArpDepoisoning() : exit");

  return retVal;
}