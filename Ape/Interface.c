#define HAVE_REMOTE

#include <pcap.h>
#include <iphlpapi.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Shlwapi.h>
#include <stdarg.h>

#include "APE.h"
#include "LinkedListSystems.h"
#include "Logging.h"
#include "NetworkFunctions.h"
#include "PacketProxy.h"



/*
 *
 *
 */
int ListInterfaceDetails()
{
  int retVal = 0;
  PIP_ADAPTER_INFO adapterInfoPtr = NULL;
  PIP_ADAPTER_INFO adapterPtr = NULL;
  DWORD functRetVal = 0;
  UINT counter;
  struct tm timestamp;
  char tempBuffer[MAX_BUF_SIZE +1 ];
  errno_t error;
  ULONG outputBufferLength = sizeof (IP_ADAPTER_INFO);

  if ((adapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, sizeof (IP_ADAPTER_INFO))) == NULL)
  {
    LogMsg(DBG_ERROR, "listIFCDetails(): Error allocating memory needed to call GetAdaptersinfo");
    retVal = 1;
    goto END;
  }

  if (GetAdaptersInfo(adapterInfoPtr, &outputBufferLength) == ERROR_BUFFER_OVERFLOW) 
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
    if ((adapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, outputBufferLength)) == NULL)
    {
      LogMsg(DBG_ERROR, "listIFCDetails(): Error allocating memory needed to call GetAdaptersinfo");
      retVal = 2;

      goto END;
    }
  }


  //
  if ((functRetVal = GetAdaptersInfo(adapterInfoPtr, &outputBufferLength)) == NO_ERROR) 
  {
    for (adapterPtr = adapterInfoPtr; adapterPtr; adapterPtr = adapterPtr->Next)
    {
      printf("\n\nIfc no : %d\n", adapterPtr->ComboIndex);
      printf("\tAdapter Name: \t%s\n", adapterPtr->AdapterName);
      printf("\tAdapter Desc: \t%s\n", adapterPtr->Description);
      printf("\tAdapter Addr: \t");

      for (counter = 0; counter < adapterPtr->AddressLength; counter++) 
      {
        if (counter == (adapterPtr->AddressLength - 1))
        {
          printf("%.2X\n", (int)adapterPtr->Address[counter]);
        }
        else
        {
          printf("%.2X-", (int)adapterPtr->Address[counter]);
        }
      } 

      printf("\tIndex: \t%d\n", adapterPtr->Index);
      printf("\tType: \t");

      switch (adapterPtr->Type) 
      {
        case MIB_IF_TYPE_OTHER:
          printf("Other\n");
          break;
        case MIB_IF_TYPE_ETHERNET:
          printf("Ethernet\n");
          break;
        case MIB_IF_TYPE_TOKENRING:
          printf("Token Ring\n");
          break;
        case MIB_IF_TYPE_FDDI:
          printf("FDDI\n");
          break;
        case MIB_IF_TYPE_PPP:
          printf("PPP\n");
          break;
        case MIB_IF_TYPE_LOOPBACK:
          printf("Lookback\n");
          break;
        case MIB_IF_TYPE_SLIP:
          printf("Slip\n");
          break;
        default:
          printf("Unknown type %ld\n", adapterPtr->Type);
          break;
      }

      printf("\tIP Address: \t%s\n", adapterPtr->IpAddressList.IpAddress.String);
      printf("\tIP Mask: \t%s\n", adapterPtr->IpAddressList.IpMask.String);
      printf("\tGateway: \t%s\n", adapterPtr->GatewayList.IpAddress.String);

      if (adapterPtr->DhcpEnabled) 
      {
        printf("\tDHCP Enabled: Yes\n");
        printf("\t  DHCP Server: \t%s\n", adapterPtr->DhcpServer.IpAddress.String);
        printf("\t  Lease Obtained: ");

        if (error = _localtime32_s(&timestamp, (__time32_t*)&adapterPtr->LeaseObtained))
        {
          printf("Invalid Argument to _localtime32_s\n");
        }
        else  if (error = asctime_s(tempBuffer, sizeof(tempBuffer), &timestamp))
        {
          printf("Invalid Argument to asctime_s\n");
        }
        else
        {
          printf("%s", tempBuffer);
        }

        printf("\t  Lease Expires:  ");

        if (error = _localtime32_s(&timestamp, (__time32_t*)&adapterPtr->LeaseExpires))
        {
          printf("Invalid Argument to _localtime32_s\n");
        }
        else if (error = asctime_s(tempBuffer, sizeof(tempBuffer), &timestamp))
        {
          printf("Invalid Argument to asctime_s\n");
        }
        else
        {
          printf("%s", tempBuffer);
        }
      } 
      else
      {
        printf("\tDHCP Enabled: No\n");
      }

      if (adapterPtr->HaveWins) 
      {
        printf("\tHave Wins: Yes\n");
        printf("\t  Primary Wins Server:    %s\n", adapterPtr->PrimaryWinsServer.IpAddress.String);
        printf("\t  Secondary Wins Server:  %s\n", adapterPtr->SecondaryWinsServer.IpAddress.String);
      } 
      else
      {
        printf("\tHave Wins: No\n");
      }
    }
  }
  else
  {
    LogMsg(DBG_ERROR, "listIFCDetails(): GetAdaptersInfo failed with error: %d\n", functRetVal);
  }

END:
  if (adapterInfoPtr)
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);

  return retVal;
}



/*
 *
 *
 */
int GetInterfaceDetails(char *interfacenameParam, PSCANPARAMS scanParamsParam)
{
  int retVal = 0;
  unsigned long localIpBin = 0;
  unsigned long gatewaiIpBin = 0;
  ULONG gatewayMacBin[2];
  ULONG gatewayMacBinLength = 6;
  PIP_ADAPTER_INFO adapterInfoPtr = NULL;
  PIP_ADAPTER_INFO adapterPtr = NULL;
  DWORD funcRetVal = 0;
  ULONG outputBufferLength = sizeof (IP_ADAPTER_INFO);

  if ((adapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, sizeof (IP_ADAPTER_INFO))) == NULL)
  {
    LogMsg(DBG_ERROR, "getIFCDetails(): Error allocating memory needed to call GetAdaptersinfo");
    retVal = 1;
    goto END;
  }

  if (GetAdaptersInfo(adapterInfoPtr, &outputBufferLength) == ERROR_BUFFER_OVERFLOW) 
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
    if ((adapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, outputBufferLength)) == NULL)
    {
      LogMsg(DBG_ERROR, "getIFCDetails(): Error allocating memory needed to call GetAdaptersinfo");
      retVal = 2;
      goto END;
    }
  }

  /*
   *
   */
  if ((funcRetVal = GetAdaptersInfo(adapterInfoPtr, &outputBufferLength)) == NO_ERROR) 
  {
    for (adapterPtr = adapterInfoPtr; adapterPtr; adapterPtr = adapterPtr->Next)
    {
      if (StrStrI(adapterPtr->AdapterName, interfacenameParam))
      {
        // Get local MAC address
        CopyMemory(scanParamsParam->LocalMacBin, adapterPtr->Address, BIN_MAC_LEN);

        // Get local IP address
        localIpBin = inet_addr(adapterPtr->IpAddressList.IpAddress.String);
        CopyMemory(scanParamsParam->LocalIpBin, &localIpBin, 4);

        // Get gateway IP address
        gatewaiIpBin = inet_addr(adapterPtr->GatewayList.IpAddress.String);
        CopyMemory(scanParamsParam->GatewayIpBin, &gatewaiIpBin, 4);

        // Get gateway MAC address
        CopyMemory(scanParamsParam->GatewayIpBin, &gatewaiIpBin, 4); // ????
        ZeroMemory(&gatewayMacBin, sizeof(gatewayMacBin));
        SendARP(gatewaiIpBin, 0, gatewayMacBin, &gatewayMacBinLength);
        CopyMemory(scanParamsParam->GatewayMacBin, gatewayMacBin, 6);

        // Get interface index.
        scanParamsParam->Index = adapterPtr->Index;

        // Get interface alias.
        GetAliasByIfcIndex(scanParamsParam->Index, (char *) scanParamsParam->InterfaceAlias, sizeof(scanParamsParam->InterfaceAlias)-1);

        // Get interface description
        CopyMemory(scanParamsParam->InterfaceDescr, adapterPtr->Description, sizeof(scanParamsParam->InterfaceDescr) - 1);

        break;
      }
    }
  }
  else
  {
    retVal = 1;
  }

END:
  if (adapterInfoPtr)
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
  }

  return retVal;
}




/*
 *
 *
 */
int GetInterfaceName(char *interfaceNameParam, char *realInterfaceNameParam, int bufferLengthParam)
{
  int retVal = 0;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  char adapter[MAX_BUF_SIZE + 1];
  int counter = 0;
  int interfaceNumber = 0;
  
  /*
   * Open device list.
   */ 
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, tempBuffer) == -1)
  {
    LogMsg(DBG_ERROR, "getIFCName(): Error in pcap_findalldevs_ex(): %s", tempBuffer);
    retVal = 1;
    goto END;
  }


  ZeroMemory(adapter, sizeof(adapter));
  counter = 0;

  for (counter = 0, device = allDevices; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, interfaceNameParam))
    {
      strncpy(realInterfaceNameParam, device->name, bufferLengthParam);
      break;
    }
  }


END:

  // Release all allocated resources.
  if (allDevices)
    pcap_freealldevs(allDevices);

  return retVal;
}

