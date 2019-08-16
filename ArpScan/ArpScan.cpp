#define HAVE_REMOTE

#include <stdio.h>
#include <pcap.h>
#include <Windows.h>
#include <Shlwapi.h>
#include <iphlpapi.h>

#include "ARPScan.h"
#include "LinkedListSystems.h"


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wpcap.lib")

// Warning C4996: This function or variable may be unsafe ... use _CRT_SECURE_NO_WARNINGS. 
// See online help for details.
#pragma warning(disable: 4996)


/*
 * Global variables
 *
 */
CRITICAL_SECTION gWriteLog;
CRITICAL_SECTION gCSSystemsLL;
PSYSTEMNODE gSystemsList = NULL;
BOOL gVerbose = FALSE;
BOOL gXml = FALSE;



/*
 * Program entry point
 * Programm call : argv[0] Ifc StartIP StopIP
 *
 */
int main(int argc, char** argv)
{
  DWORD retVal = 0;
  ARPPacket arpPacket;
  SCANPARAMS scanParams;
  unsigned long ipCounter = 0;
  unsigned long ipCounterHostOrder = 0;
  unsigned long dstIP = 0;
  HANDLE threadHandle = INVALID_HANDLE_VALUE;
  DWORD threadId = 0;
  int counter = 0;
  char temp[PCAP_ERRBUF_SIZE];

  HANDLE icmpFile = INVALID_HANDLE_VALUE;
  char sendData[32] = "Data Buffer";
  DWORD replySize = 0;
  LPVOID replyBuffer = NULL;
  unsigned long ipaddr = 0;
  HANDLE arpReplyThreadHandle = INVALID_HANDLE_VALUE;
  DWORD arpReplyThreadID = 0;
  struct sockaddr_in peerIp;
  char peerIpStr[MAX_BUF_SIZE + 1];
  char adapter[MAX_BUF_SIZE + 1];


  ZeroMemory(adapter, sizeof(adapter));
  ZeroMemory(&scanParams, sizeof(scanParams));
  ZeroMemory(&arpPacket, sizeof(arpPacket));
   
  // Initialisation
  InitializeCriticalSectionAndSpinCount(&gWriteLog, 0x00000400);
  InitializeCriticalSectionAndSpinCount(&gCSSystemsLL, 0x00000400);

  ParseInputParams(argc, argv);
  gSystemsList = InitSystemList();
  PreparePcapDevice(argv[1], adapter);
  GetIfcDetails(adapter, &scanParams);

  strncpy(scanParams.IFCstring, adapter, sizeof(scanParams.IFCstring) - 1);
  scanParams.StartIPNum = ntohl(inet_addr(argv[2]));
  scanParams.StopIPNum = ntohl(inet_addr(argv[3]));

  ParseScanParams(&scanParams, adapter);

  if ((arpReplyThreadHandle = CreateThread(NULL, 0, CaptureArpReplies, &scanParams, 0, &arpReplyThreadID)) == NULL)
  {
    exit(8);
  }

  for (ipCounter = scanParams.StartIPNum; ipCounter <= scanParams.StopIPNum; ipCounter++)
  {
    if (memcmp(scanParams.LocalIP, &ipCounter, BIN_IP_LEN) &&
        memcmp(scanParams.GWIP, &ipCounter, BIN_IP_LEN))
    {
      // Send WhoHas ARP request and sleep ...
      SendArpWhoHas(&scanParams, ipCounter);
      peerIp.sin_addr.s_addr = htonl(ipCounter);
      strncpy(peerIpStr, inet_ntoa(peerIp.sin_addr), sizeof(peerIpStr) - 1);


      if (gVerbose == TRUE)
      {
        ZeroMemory(temp, sizeof(temp));
        if (gXml == TRUE)
          _snprintf(temp, sizeof(temp) - 1, "<arp>\n  <type>request</type>\n  <ip>%s</ip>\n  <mac></mac>\n</arp>", peerIpStr);
        else
          _snprintf(temp, sizeof(temp) - 1, "request;%s;", peerIpStr);

        LogMsg(temp);
      }

      Sleep(SLEEP_BETWEEN_ARPS);
    }
  }

  // Wait for all ARP replies and terminate thread.
  Sleep(5000);
  TerminateThread(arpReplyThreadHandle, 0);
  CloseHandle(arpReplyThreadHandle);

  if (scanParams.IfcWriteHandle)
    pcap_close((pcap_t*)scanParams.IfcWriteHandle);

END:

  DeleteCriticalSection(&gWriteLog);
  DeleteCriticalSection(&gCSSystemsLL);

  return retVal;
}



DWORD WINAPI CaptureArpReplies(LPVOID pScanParams)
{
  pcap_t* ifcHandle = NULL;
  char temp[1024];
  int pcapRetVal = 0;
  PETHDR ethrHdr = NULL;
  PARPHDR arpPHdr = NULL;
  u_char* pktData = NULL;
  struct pcap_pkthdr* pktHdr = NULL;
  PSCANPARAMS scanParams = (PSCANPARAMS)pScanParams;
  unsigned char tmpPkt[256];
  unsigned int tmpSize;
  unsigned char ethDstStr[MAX_MAC_LEN + 1];
  unsigned char ethSrcStr[MAX_MAC_LEN + 1];
  unsigned char arpEthDstStr[MAX_MAC_LEN + 1];
  unsigned char arpEthSrcStr[MAX_MAC_LEN + 1];
  unsigned char arpIpDstStr[MAX_IP_LEN + 1];
  unsigned char arpIpSrcStr[MAX_IP_LEN + 1];

  if ((ifcHandle = pcap_open((char*)scanParams->IFCstring, 64, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, temp)) == NULL)
  {
    goto END;
  }
  
  while ((pcapRetVal = pcap_next_ex(ifcHandle, &pktHdr, (const u_char * *)& pktData)) >= 0)
  {
    if (pcapRetVal == 1)
    {
      tmpSize = pktHdr->len > 255 ? 255 : pktHdr->len;
      ZeroMemory(tmpPkt, 256);
      CopyMemory(tmpPkt, pktData, tmpSize);
      
      ethrHdr = (PETHDR)tmpPkt;
      arpPHdr = (PARPHDR)(tmpPkt + sizeof(ETHDR));

      if (ntohs(arpPHdr->oper) == ARP_REPLY)
      {
        ZeroMemory(ethDstStr, sizeof(ethDstStr));
        ZeroMemory(ethSrcStr, sizeof(ethSrcStr));
        ZeroMemory(arpEthSrcStr, sizeof(arpEthSrcStr));
        ZeroMemory(arpEthDstStr, sizeof(arpEthDstStr));
        ZeroMemory(arpIpDstStr, sizeof(arpIpDstStr));
        ZeroMemory(arpIpSrcStr, sizeof(arpIpSrcStr));

        Mac2String(ethrHdr->ether_shost, ethSrcStr, sizeof(ethSrcStr) - 1);
        Mac2String(ethrHdr->ether_dhost, ethDstStr, sizeof(ethDstStr) - 1);
        Mac2String(arpPHdr->sha, arpEthSrcStr, sizeof(arpEthSrcStr) - 1);
        Mac2String(arpPHdr->tha, arpEthDstStr, sizeof(arpEthDstStr) - 1);
        
        Ip2string(arpPHdr->tpa, arpIpDstStr, sizeof(arpIpDstStr) - 1);
        Ip2string(arpPHdr->spa, arpIpSrcStr, sizeof(arpIpSrcStr) - 1);
        
        if (GetNodeByMac(gSystemsList, arpPHdr->sha) == NULL)
        {
          AddToList(&gSystemsList, arpPHdr->spa, arpPHdr->sha);

          ZeroMemory(temp, sizeof(temp));
          if (gXml == TRUE)
          _snprintf(temp, sizeof(temp) - 1, "<arp>\n  <type>reply</type>\n  <ip>%s</ip>\n  <mac>%s</mac>\n</arp>", arpIpSrcStr, ethSrcStr);
          else
            _snprintf(temp, sizeof(temp) - 1, "reply;%s;%s", arpIpSrcStr, ethSrcStr);

          LogMsg(temp);
        }
      }
    }
  }

END:

  return 0;
}

/*
 * Ethr:	LocalMAC -> 255:255:255:255:255:255a
 * ARP :	LocMAC/LocIP -> 0:0:0:0:0:0/VicIP
 *
 */
int SendArpWhoHas(PSCANPARAMS pScanParams, unsigned long lIPAddress)
{
  int retVal = OK;
  unsigned long dstIp = 0;
  ARPPacket arpPacket;
  int i = 0;

  dstIp = htonl(lIPAddress);
  arpPacket.lReqType = ARP_REQUEST;

  // Set src/dst MAC values
  CopyMemory(arpPacket.Eth_SrcMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
  memset(arpPacket.Eth_DstMAC, 255, sizeof(arpPacket.Eth_DstMAC));

  // Set ARP request values
  CopyMemory(arpPacket.ARP_LocalMAC, pScanParams->LocalMAC, BIN_MAC_LEN);
  CopyMemory(arpPacket.ARP_LocalIP, pScanParams->LocalIP, BIN_IP_LEN);
  CopyMemory(&arpPacket.ARP_DstIP[0], &dstIp, BIN_IP_LEN);

  // Send packet
  if (SendArpPacket(pScanParams->IfcWriteHandle, &arpPacket) != 0)
  {
    //    LogMsg("SendARPWhoHas() : Unable to send ARP packet.\n");
    retVal = NOK;
  }

  return retVal;
}


int SendArpPacket(void* pIFCHandle, PARPPacket pARPPacket)
{
  int retVal = NOK;
  unsigned char arpPacket[sizeof(ETHDR) + sizeof(ARPHDR)];
  int lCounter = 0;
  PETHDR ethrHdr = (PETHDR)arpPacket;
  PARPHDR arpHdr = (PARPHDR)(arpPacket + 14);

  ZeroMemory(arpPacket, sizeof(arpPacket));

  // Layer 2 (Physical)
  CopyMemory(ethrHdr->ether_shost, pARPPacket->Eth_SrcMAC, BIN_MAC_LEN);
  CopyMemory(ethrHdr->ether_dhost, pARPPacket->Eth_DstMAC, BIN_MAC_LEN);
  ethrHdr->ether_type = htons(ETHERTYPE_ARP);

  // Layer 2/3
  arpHdr->htype = htons(0x0001); // Ethernet
  arpHdr->ptype = htons(0x0800); // Protocol type on the upper layer : IP
  arpHdr->hlen = 0x0006; // Ethernet address length : 6
  arpHdr->plen = 0x0004; // Number of octets in upper protocol layer : 4
  arpHdr->oper = htons(pARPPacket->lReqType);

  CopyMemory(arpHdr->tpa, pARPPacket->ARP_DstIP, BIN_IP_LEN);
  CopyMemory(arpHdr->tha, pARPPacket->ARP_Dst_MAC, BIN_MAC_LEN);

  CopyMemory(arpHdr->spa, pARPPacket->ARP_LocalIP, BIN_IP_LEN);
  CopyMemory(arpHdr->sha, pARPPacket->ARP_LocalMAC, BIN_MAC_LEN);

  // Send down the packet
  if (pIFCHandle != NULL && pcap_sendpacket((pcap_t*)pIFCHandle, arpPacket, sizeof(ETHDR) + sizeof(ARPHDR)) == 0)
    retVal = OK;
  //  else
  // 	  LogMsg("SendARPPacket() : Error occured while sending the packet: %s\n", pcap_geterr((pcap_t *) pIFCHandle));
  
  return retVal;
}


void Mac2String(unsigned char mac[BIN_MAC_LEN], unsigned char* output, int outputLen)
{
  if (output && outputLen > 0)
    _snprintf((char*)output, outputLen, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


void Ip2string(unsigned char ip[BIN_IP_LEN], unsigned char* output, int outputLen)
{
  if (output && outputLen > 0)
    _snprintf((char*)output, outputLen, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}


int GetIfcDetails(char* ifcName, PSCANPARAMS scanParams)
{
  int retVal = 0;
  unsigned long localIpAddr = 0;
  unsigned long gwIpAddr = 0;
  ULONG gwMacAddr[2];
  ULONG gwMacAddrLen = 6;
  PIP_ADAPTER_INFO adapterInfoPtr = NULL;
  PIP_ADAPTER_INFO adapter = NULL;
  DWORD funcRetVal = 0;
  ULONG outBufLen = sizeof(IP_ADAPTER_INFO);

  if ((adapterInfoPtr = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO))) == NULL)
  {
    retVal = 1;
    goto END;
  }

  if (GetAdaptersInfo(adapterInfoPtr, &outBufLen) == ERROR_BUFFER_OVERFLOW)
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
    if ((adapterInfoPtr = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, outBufLen)) == NULL)
    {
      retVal = 2;
      goto END;
    }
  }

  //
  if ((funcRetVal = GetAdaptersInfo(adapterInfoPtr, &outBufLen)) == NO_ERROR)
  {
    for (adapter = adapterInfoPtr; adapter; adapter = adapter->Next)
    {
      if (StrStrI(ifcName, adapter->AdapterName))
      {
        // Get local MAC address
        CopyMemory(scanParams->LocalMAC, adapter->Address, BIN_MAC_LEN);

        // Get local IP address
        localIpAddr = inet_addr(adapter->IpAddressList.IpAddress.String);
        CopyMemory(scanParams->LocalIP, &localIpAddr, 4);

        // Get gateway IP address
        gwIpAddr = inet_addr(adapter->GatewayList.IpAddress.String);
        CopyMemory(scanParams->GWIP, &gwIpAddr, 4);

        // Get gateway MAC address
        CopyMemory(scanParams->GWIP, &gwIpAddr, 4); // ????
        ZeroMemory(&gwMacAddr, sizeof(gwMacAddr));
        SendARP(gwIpAddr, 0, gwMacAddr, &gwMacAddrLen);
        CopyMemory(scanParams->GWMAC, gwMacAddr, 6);

        // Get interface index.
        scanParams->Index = adapter->Index;

        // Get interface description
        CopyMemory(scanParams->IFCDescr, adapter->Description, sizeof(scanParams->IFCDescr) - 1);

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


void LogMsg(char* msg, ...)
{
  HANDLE fileHandle = INVALID_HANDLE_VALUE;
  OVERLAPPED overlapped = { 0 };
  char temp[MAX_BUF_SIZE + 1];
  char logMsg[MAX_BUF_SIZE + 1];
  DWORD byteWritten = 0;
  va_list args;

  EnterCriticalSection(&gWriteLog);

  /*
   * Create log message
   */
  ZeroMemory(temp, sizeof(temp));
  ZeroMemory(logMsg, sizeof(logMsg));
  va_start(args, msg);
  vsprintf(temp, msg, args);
  va_end(args);
  _snprintf(logMsg, sizeof(logMsg) - 1, "%s\n", temp);
  fprintf(stdout, logMsg);
  //fprintf(stderr, lLogMsg);
  fflush(stdout);
  //fflush(stderr);

  LeaveCriticalSection(&gWriteLog);
}


void PrintUsage(char* pAppName)
{
  system("cls");
  printf("List all interfaces               :  %s -l\n", pAppName);
  printf("Print help                        :  %s (-h|-?)\n", pAppName);
  printf("Scan network                      :  %s IFC-ID Start-IP Stop-IP\n", pAppName);
  printf("Print verbose scan output         :  %s IFC-ID Start-IP Stop-IP -v\n", pAppName);
  printf("Print scan output in XML          :  %s IFC-ID Start-IP Stop-IP -x\n", pAppName);
  printf("\n\n\n\nExamples\n--------\n\n");
  printf("Example : %s 0F716AAF-D4A7-ACBA-1234-EA45A939F624 192.168.0.1 192.168.0.255\n", pAppName);
}


void ListInterfaceDetails()
{
  int retVal = 0;
  PIP_ADAPTER_INFO adapterInfoPtr = NULL;
  PIP_ADAPTER_INFO adapterPtr = NULL;
  DWORD functRetVal = 0;
  UINT counter;
  struct tm timestamp;
  char tempBuffer[MAX_BUF_SIZE + 1];
  errno_t error;
  ULONG outputBufferLength = sizeof(IP_ADAPTER_INFO);

  if ((adapterInfoPtr = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, sizeof(IP_ADAPTER_INFO))) == NULL)
  {
    fprintf(2, "listIFCDetails(): Error allocating memory needed to call GetAdaptersinfo");
    retVal = 1;
    goto END;
  }

  if (GetAdaptersInfo(adapterInfoPtr, &outputBufferLength) == ERROR_BUFFER_OVERFLOW)
  {
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);
    if ((adapterInfoPtr = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, outputBufferLength)) == NULL)
    {
      fprintf(2, "listIFCDetails(): Error allocating memory needed to call GetAdaptersinfo");
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

        if (error = _localtime32_s(&timestamp, (__time32_t*)& adapterPtr->LeaseObtained))
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

        if (error = _localtime32_s(&timestamp, (__time32_t*)& adapterPtr->LeaseExpires))
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
  fprintf(2, "listIFCDetails(): GetAdaptersInfo failed with error: %d\n", functRetVal);
  }

END:
  if (adapterInfoPtr)
    HeapFree(GetProcessHeap(), 0, adapterInfoPtr);

  return retVal;
}


BOOL IsFlagSet(int argc, char** argv, char* flag)
{
  BOOL retVal = FALSE;

  if (flag == NULL ||
    strnlen(flag, 3) != 2)
  {
    printf("IsFlagSet(): 0\r\n");
    return FALSE;
  }

  if (argc < 2)
  {
    printf("IsFlagSet(): 1\r\n");
    return FALSE;
  }

  for (int i = 1; i < argc; i++)
  {
    if (strcmpi(argv[i], flag, 2) == 0)
    {
      return TRUE;
    }
  }

  return FALSE;
}


void ParseInputParams(int argc, char** argv)
{
  if (IsFlagSet(argc, argv, "-l") == TRUE)
  {
    ListInterfaceDetails();
    exit(0);
  }
  else if (IsFlagSet(argc, argv, "-h") == TRUE ||
    IsFlagSet(argc, argv, "-?") == TRUE)
  {
    PrintUsage(argv[0]);
    exit(0);
  }

  if (argc < 4)
  {
    PrintUsage(argv[0]);
    exit(0);
  }

  gXml = IsFlagSet(argc, argv, "-x");
  gVerbose = IsFlagSet(argc, argv, "-v");
}


void ParseScanParams(PSCANPARAMS scanParams, char *adapter)
{
  char filter[1024];
  bpf_u_int32 netMask;
  struct bpf_program fCode;
  char temp[PCAP_ERRBUF_SIZE];

  ZeroMemory(&fCode, sizeof(fCode));
  ZeroMemory(filter, sizeof(filter));

  _snprintf(filter, sizeof(filter) - 1, "arp and arp[6:2] = 2");
  //netMask = 0xffffff; // "255.255.255.0"

  if (scanParams->StartIPNum > scanParams->StopIPNum)
  {
    exit(4);
  }

  // Start ARP Reply listener thread
  if ((scanParams->IfcWriteHandle = pcap_open(adapter, 48, PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1, NULL, temp)) == NULL)
  {
    printf("adapter: %s\n", adapter);
    exit(5);
  }

  // if (pcap_compile((pcap_t *) lScanParams.IfcWriteHandle, &lFCode, (const char *) lFilter, 1, lNetMask) >= 0)
  if (pcap_compile((pcap_t*)scanParams->IfcWriteHandle, &fCode, (const char*)filter, 1, NULL) < 0)
  {
    exit(6);
  }

  // Set the filter
  if (pcap_setfilter((pcap_t*)scanParams->IfcWriteHandle, &fCode) < 0)
  {
    exit(7);
  }
}


void PreparePcapDevice(char *ifcName, char *adapter)
{
  int counter = 0;
  char temp[PCAP_ERRBUF_SIZE];
  pcap_if_t* allDevs = NULL;
  pcap_if_t* device = NULL;

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevs, temp) == -1)
  {
    exit(2);
  }

  for (counter = 0, device = allDevs; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, ifcName))
    {
      strcpy(adapter, device->name);
      break;
    }
  }

  // We dont need this list anymore.
  pcap_freealldevs(allDevs);

  if (adapter == NULL ||
      strnlen(adapter, sizeof(adapter) - 1) <= 0)
  {
    exit(3);
  }
}