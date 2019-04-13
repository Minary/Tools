#define HAVE_REMOTE

#include <pcap.h>
#include <iphlpapi.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Shlwapi.h>
#include <stdarg.h>

#include "Sniffer.h"
#include "GenericSniffer.h"
#include "LinkedListSystems.h"
#include "LinkedListConnections.h"
#include "Logging.h"
#include "NetworkFunctions.h"



int ListInterfaceDetails()
{
  int retVal = 0;
  PIP_ADAPTER_INFO adapterInfoPtr = NULL;
  PIP_ADAPTER_INFO adapter = NULL;
  DWORD funcRetVal = 0;
  UINT counter;
  struct tm timeStamp;
  char tempBuffer[MAX_BUF_SIZE + 1];
  errno_t error;
  ULONG outputBufferLength = sizeof(IP_ADAPTER_INFO);

  if ((adapterInfoPtr = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO))) == NULL)
  {
    LogMsg(DBG_ERROR, "listIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
    retVal = 1;
    goto END;
  }

  if (GetAdaptersInfo(adapterInfoPtr, &outputBufferLength) == ERROR_BUFFER_OVERFLOW)
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
    if ((adapterInfoPtr = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, outputBufferLength)) == NULL)
    {
      LogMsg(DBG_ERROR, "listIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
      retVal = 2;

      goto END;
    }
  }


  //
  if ((funcRetVal = GetAdaptersInfo(adapterInfoPtr, &outputBufferLength)) == NO_ERROR)
  {
    for (adapter = adapterInfoPtr; adapter; adapter = adapter->Next)
    {
      printf("\n\nIfc no : %d\n", adapter->ComboIndex);
      printf("\tAdapter Name: \t%s\n", adapter->AdapterName);
      printf("\tAdapter Desc: \t%s\n", adapter->Description);
      printf("\tAdapter Addr: \t");

      for (counter = 0; counter < adapter->AddressLength; counter++)
      {
        if (counter == (adapter->AddressLength - 1))
        {
          printf("%.2X\n", (int)adapter->Address[counter]);
        }
        else
        {
          printf("%.2X-", (int)adapter->Address[counter]);
        }
      }

      printf("\tIndex: \t%d\n", adapter->Index);
      printf("\tType: \t");

      switch (adapter->Type)
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
          printf("Unknown type %ld\n", adapter->Type);
          break;
      }

      printf("\tIP Address: \t%s\n", adapter->IpAddressList.IpAddress.String);
      printf("\tIP Mask: \t%s\n", adapter->IpAddressList.IpMask.String);
      printf("\tGateway: \t%s\n", adapter->GatewayList.IpAddress.String);

      if (adapter->DhcpEnabled)
      {
        printf("\tDHCP Enabled: Yes\n");
        printf("\t  DHCP Server: \t%s\n", adapter->DhcpServer.IpAddress.String);
        printf("\t  Lease Obtained: ");

        if (error = _localtime32_s(&timeStamp, (__time32_t*)&adapter->LeaseObtained))
        {
          printf("Invalid Argument to _localtime32_s\n");
        }
        else
        {
          if (error = asctime_s(tempBuffer, sizeof(tempBuffer), &timeStamp))
          {
            printf("Invalid Argument to asctime_s\n");
          }
          else
          {
            printf("%s", tempBuffer);
          }
        }

        printf("\t  Lease Expires:  ");
        if (error = _localtime32_s(&timeStamp, (__time32_t*)&adapter->LeaseExpires))
        {
          printf("Invalid Argument to _localtime32_s\n");
        }
        else if (error = asctime_s(tempBuffer, sizeof(tempBuffer), &timeStamp))
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

      if (adapter->HaveWins)
      {
        printf("\tHave Wins: Yes\n");
        printf("\t  Primary Wins Server:    %s\n", adapter->PrimaryWinsServer.IpAddress.String);
        printf("\t  Secondary Wins Server:  %s\n", adapter->SecondaryWinsServer.IpAddress.String);
      }
      else
      {
        printf("\tHave Wins: No\n");
      }
    }
  }
  else
  {
    LogMsg(DBG_ERROR, "listIFCDetails() : GetAdaptersInfo failed with error: %d\n", funcRetVal);
  }

END:
  if (adapterInfoPtr)
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
  }

  return retVal;
}



int GetInterfaceDetails(char *ifcName, PSCANPARAMS scanParams)
{
  int retVal = 0;
  unsigned long ocalIpBin = 0;
  unsigned long gatewayIpBin = 0;
  ULONG gatewayMacBin[2];
  ULONG gatewayMacBinLength = 6;
  PIP_ADAPTER_INFO adapterInfoPtr = NULL;
  PIP_ADAPTER_INFO adapter = NULL;
  DWORD funcRetVal = 0;
  ULONG outputBufferLength = sizeof(IP_ADAPTER_INFO);
  
  if ((adapterInfoPtr = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO))) == NULL)
  {
    LogMsg(DBG_ERROR, "getIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
    retVal = 1;
    goto END;
  }
  
  if (GetAdaptersInfo(adapterInfoPtr, &outputBufferLength) == ERROR_BUFFER_OVERFLOW)
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
    if ((adapterInfoPtr = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, outputBufferLength)) == NULL)
    {
      LogMsg(DBG_ERROR, "getIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
      retVal = 2;
      goto END;
    }
  }

  //
  if ((funcRetVal = GetAdaptersInfo(adapterInfoPtr, &outputBufferLength)) == NO_ERROR)
  {
    for (adapter = adapterInfoPtr; adapter; adapter = adapter->Next)
    {
      if (StrStrI(adapter->AdapterName, ifcName))
      {
        // Get local MAC address
        CopyMemory(scanParams->LocalMAC, adapter->Address, BIN_MAC_LEN);

        // Get local IP address
        ocalIpBin = inet_addr(adapter->IpAddressList.IpAddress.String);
        CopyMemory(scanParams->LocalIP, &ocalIpBin, 4);

        // Get gateway IP address
        gatewayIpBin = inet_addr(adapter->GatewayList.IpAddress.String);
        CopyMemory(scanParams->GWIP, &gatewayIpBin, 4);

        // Get gateway MAC address
        CopyMemory(scanParams->GWIP, &gatewayIpBin, 4); // ????
        ZeroMemory(&gatewayMacBin, sizeof(gatewayMacBin));
        SendARP(gatewayIpBin, 0, gatewayMacBin, &gatewayMacBinLength);
        CopyMemory(scanParams->GWMAC, gatewayMacBin, 6);

        // Get interface index.
        scanParams->Index = adapter->Index;

        // Get interface alias.
        GetAliasByIfcIndex(scanParams->Index, (char *)scanParams->IfcAlias, sizeof(scanParams->IfcAlias) - 1);

        // Get interface description
        CopyMemory(scanParams->IfcDescr, adapter->Description, sizeof(scanParams->IfcDescr) - 1);

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
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);

  return retVal;
}



int GetInterfaceName(char *ifcName, char *realIfcName, int bufferSize)
{
  int retVal = 0;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  char adapter[MAX_BUF_SIZE + 1];
  int counter = 0;
  int ifcNumber = 0;

  // Open device list.
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, tempBuffer) == -1)
  {
    LogMsg(DBG_ERROR, "GetInterfaceName() : Error in pcap_findalldevs_ex() : %s", tempBuffer);
    retVal = 1;
    goto END;
  }

  ZeroMemory(adapter, sizeof(adapter));
  for (counter = 0, device = allDevices; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, ifcName))
    {
      strncpy(realIfcName, device->name, bufferSize);
      break;
    }
  }

END:

  // Release all allocated resources.
  if (counter > 0 &&
      allDevices != NULL)
  {
    pcap_freealldevs(allDevices);
  }

  return retVal;
}

