#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>

#include "APESniffer.h"
#include "DnsParser.h"
#include "LinkedListConnections.h"
#include "LinkedListSystems.h"
#include "Logging.h"
#include "ModeMinary.h"
#include "NetworkFunctions.h"


extern int gDEBUGLEVEL;
extern char gTempFilesDir[MAX_BUF_SIZE + 1];
extern CRITICAL_SECTION gCSOutputPipe;
extern PCONNODE gConnectionList;

PSYSNODE gTargetSystemsList;
SCANPARAMS gCurrentScanParams;
HANDLE gOutputPipe = INVALID_HANDLE_VALUE;



int ModeMinaryStart(PSCANPARAMS scanParamsParam)
{
  int retVal = 0;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  char adapter[MAX_BUF_SIZE + 1];
  char bpfFilter[MAX_BUF_SIZE + 1];
  int counter = 0;
  int interfaceNumber = 0;
  struct bpf_program filterCode;
  unsigned int netMask = 0;
  char namedPipePath[MAX_BUF_SIZE + 1];

  PSCANPARAMS tempParams = (PSCANPARAMS)scanParamsParam;
  SECURITY_ATTRIBUTES pipeSecurityAttribute = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

  ZeroMemory(&gCurrentScanParams, sizeof(gCurrentScanParams));
  CopyMemory(&gCurrentScanParams, tempParams, sizeof(gCurrentScanParams));

  // Initialize named pipe to write output to
  ZeroMemory(namedPipePath, sizeof(namedPipePath));
  if (gCurrentScanParams.OutputPipeName[0] != 0)
  {
    snprintf(namedPipePath, sizeof(namedPipePath) - 1, "\\\\.\\pipe\\%s", gCurrentScanParams.OutputPipeName);
    printf("Writing output to NamedPipe:%s\n", namedPipePath);
    gOutputPipe = CreateFile(namedPipePath, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  }
  else
  {
    printf("Writing out put to console\n");
  }

  // Open device list.
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevices, tempBuffer) == -1)
  {
    LogMsg(DBG_ERROR, "startSniffer() : Error in pcap_findalldevs_ex() : %s", tempBuffer);
    goto END;
  }

  ZeroMemory(adapter, sizeof(adapter));

  // Loop through all available interfaces and pick the
  // right one out.
  for (counter = 0, device = allDevices; device; device = device->next, counter++)
  {
    if (StrStrI(device->name, (char *)gCurrentScanParams.IFCName)) //pIFCName))
    {
      strcpy(adapter, device->name);
      break;
    }
  }

  if (allDevices)
  {
    pcap_freealldevs(allDevices);
  }

  // Open interface.
  if ((gCurrentScanParams.IfcReadHandle = pcap_open(adapter, 65536, PCAP_OPENFLAG_PROMISCUOUS, PCAP_READTIMEOUT, NULL, tempBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "startSniffer() : Unable to open the adapter \"%s\"", gCurrentScanParams.IFCName);
    goto END;
  }

  // Compiling + setting the filter
  if (device->addresses != NULL)
  {
    netMask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
  }
  else
  {
    netMask = 0xffffff;
  }

  ZeroMemory(&filterCode, sizeof(filterCode));
  ZeroMemory(bpfFilter, sizeof(bpfFilter));
  snprintf(bpfFilter, sizeof(bpfFilter) - 1, "dst port 80 or dst port 443 or dst port 53 or src port 53");
  if (pcap_compile((pcap_t *)gCurrentScanParams.IfcReadHandle, &filterCode, bpfFilter, 1, netMask) < 0)
  {
    LogMsg(DBG_ERROR, "startSniffer() : Unable to compile the packet filter");
  }

  if (pcap_setfilter((pcap_t *)gCurrentScanParams.IfcReadHandle, &filterCode) >= 0)
  {
    LogMsg(DBG_ERROR, "startSniffer() : Error setting the filter");
  }

  LogMsg(DBG_INFO, "startSniffer() : Scanner started. Waiting for data on device \"%s\" ...", adapter);

  // Start intercepting data packets.
  pcap_loop((pcap_t *)gCurrentScanParams.IfcReadHandle, 0, (pcap_handler)SniffAndParseCallback, (unsigned char *)&gCurrentScanParams);

END:

  return retVal;
}



void SniffAndParseCallback(unsigned char *scanParamsParam, struct pcap_pkthdr *pcapHdrParam, unsigned char *packetDataParam)
{
  SYSTEMNODE system;
  PETHDR ethrHdr = (PETHDR)packetDataParam;
  PIPHDR ipHdrPtrParam = NULL;
  PTCPHDR tcpHdrPtrParam = NULL;
  PUDPHDR udpHdrPtr = NULL;
  int ipHeaderLength = 0;
  int tcpHeaderLength = 0;
  int tcpDataLength = 0;
  unsigned char data[1500 + 1];
  unsigned char realData[1500 + 1];
  int totalLength = 0;
  unsigned char *tempBufferPtr = NULL;
  unsigned char tempBuffer[MAX_BUF_SIZE + 1];
  unsigned char tempBuffer2[MAX_BUF_SIZE + 1];
  unsigned char srcMacStr[MAX_BUF_SIZE + 1];
  unsigned char dstMacStr[MAX_BUF_SIZE + 1];
  unsigned char dstMac[MAX_BUF_SIZE + 1];
  unsigned char srcIpStr[MAX_BUF_SIZE + 1];
  unsigned char dstIpStr[MAX_BUF_SIZE + 1];
  unsigned char ipBytes[BIN_IP_LEN];
  int bufferLength = 0;
  int retVal = 0;
  int pcapRetVal = 0;
  unsigned long dstIpNumber = 0;
  int lInSubnet = 0;
  unsigned char *dataPipe = NULL;
  PSCANPARAMS tempParams = (PSCANPARAMS)scanParamsParam;
  SCANPARAMS scanParams;
  unsigned int sequenceNumber = 0;
  char hostname[MAX_BUF_SIZE + 1];
  HANDLE fileHandle = INVALID_HANDLE_VALUE;
  PSYSNODE readlDstSystem = NULL;
  PARPHDR arpData = NULL;
  unsigned short type = htons(ethrHdr->ether_type);
  char payload[1506];
  char *payloadPtr = NULL;

  ZeroMemory(&scanParams, sizeof(scanParams));
  CopyMemory(&scanParams, tempParams, sizeof(scanParams));


  // Its an IP packet and its destination is not our own system.
  // We forward it to the real gateway.
  if (type != ETHERTYPE_IP)
  {
    return;
  }

  if (memcmp(scanParams.LocalMAC, ethrHdr->ether_shost, BIN_MAC_LEN) == 0 ||
    memcmp(scanParams.LocalMAC, ethrHdr->ether_dhost, BIN_MAC_LEN) != 0)
  {
    return;
  }

  ipHdrPtrParam = (PIPHDR)(packetDataParam + 14);
  ipHeaderLength = (ipHdrPtrParam->ver_ihl & 0xf) * 4;

  ZeroMemory(srcIpStr, sizeof(srcIpStr));
  ZeroMemory(dstIpStr, sizeof(dstIpStr));
  ZeroMemory(srcMacStr, sizeof(srcMacStr));
  ZeroMemory(dstMacStr, sizeof(dstMacStr));
  ZeroMemory(dstMac, sizeof(dstMac));

  snprintf((char *)srcIpStr, sizeof(srcIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->saddr.byte1, ipHdrPtrParam->saddr.byte2, ipHdrPtrParam->saddr.byte3, ipHdrPtrParam->saddr.byte4);
  snprintf((char *)dstIpStr, sizeof(dstIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->daddr.byte1, ipHdrPtrParam->daddr.byte2, ipHdrPtrParam->daddr.byte3, ipHdrPtrParam->daddr.byte4);

  Mac2String(ethrHdr->ether_shost, srcMacStr, sizeof(srcMacStr) - 1);
  Mac2String(ethrHdr->ether_dhost, dstMacStr, sizeof(dstMacStr) - 1);

  ipBytes[0] = ipHdrPtrParam->daddr.byte1;
  ipBytes[1] = ipHdrPtrParam->daddr.byte2;
  ipBytes[2] = ipHdrPtrParam->daddr.byte3;
  ipBytes[3] = ipHdrPtrParam->daddr.byte4;

  // Dst IP is our local IP and port is 80.
  // We do this because of DNS poisoning and to evaluate traffic we
  // redirect to this system (e.g. www.facebook.com).
  //
  if (memcmp(&ipHdrPtrParam->daddr, scanParams.LocalIP, BIN_IP_LEN) == 0 &&
    ipHdrPtrParam->proto == IP_PROTO_TCP)
  {
    readlDstSystem = GetNodeByIp(gTargetSystemsList, ethrHdr->ether_dhost);
    Mac2String(ethrHdr->ether_dhost, dstMacStr, sizeof(dstMacStr) - 1);

    ZeroMemory(&system, sizeof(system));
    // Src/Dst IPs
    snprintf((char *)system.dstIpStr, sizeof(system.dstIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->daddr.byte1, ipHdrPtrParam->daddr.byte2, ipHdrPtrParam->daddr.byte3, ipHdrPtrParam->daddr.byte4);
    snprintf((char *)system.srcIpStr, sizeof(system.srcIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->saddr.byte1, ipHdrPtrParam->saddr.byte2, ipHdrPtrParam->saddr.byte3, ipHdrPtrParam->saddr.byte4);

    totalLength = ntohs(ipHdrPtrParam->tlen);
    tcpHdrPtrParam = (PTCPHDR)((u_char*)ipHdrPtrParam + ipHeaderLength);

    tcpHeaderLength = tcpHdrPtrParam->doff * 4;
    tcpDataLength = totalLength - ipHeaderLength - tcpHeaderLength;

    ZeroMemory(srcMacStr, sizeof(srcMacStr));
    Mac2String(ethrHdr->ether_shost, srcMacStr, sizeof(srcMacStr) - 1);

    // If packet is an HTTP(S) request sent by the client to the server
    // the packet is processed separately.
    if (ntohs(tcpHdrPtrParam->dport) == 80)
    {
      HandleHttpTraffic((char *)srcMacStr, ipHdrPtrParam, tcpHdrPtrParam);
    }

    // Dst IP is not our own local IP.
    // Process packet and forward it to the default GW.
  }
  else if (memcmp(&ipHdrPtrParam->saddr, scanParams.LocalIP, BIN_IP_LEN) != 0 && memcmp(&ipHdrPtrParam->daddr, scanParams.LocalIP, BIN_IP_LEN) != 0)
  {
    readlDstSystem = GetNodeByIp(gTargetSystemsList, ethrHdr->ether_dhost);
    {
      Mac2String(ethrHdr->ether_dhost, dstMacStr, sizeof(dstMacStr) - 1);

      ZeroMemory(&system, sizeof(system));
      // Src/Dst IPs
      snprintf((char *)system.dstIpStr, sizeof(system.dstIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->daddr.byte1, ipHdrPtrParam->daddr.byte2, ipHdrPtrParam->daddr.byte3, ipHdrPtrParam->daddr.byte4);
      snprintf((char *)system.srcIpStr, sizeof(system.srcIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->saddr.byte1, ipHdrPtrParam->saddr.byte2, ipHdrPtrParam->saddr.byte3, ipHdrPtrParam->saddr.byte4);

      // Process TCP data
      if (ipHdrPtrParam->proto == IP_PROTO_TCP)
      {
        totalLength = ntohs(ipHdrPtrParam->tlen);
        tcpHdrPtrParam = (PTCPHDR)((u_char*)ipHdrPtrParam + ipHeaderLength);

        tcpHeaderLength = tcpHdrPtrParam->doff * 4;
        tcpDataLength = totalLength - ipHeaderLength - tcpHeaderLength;

        ZeroMemory(srcMacStr, sizeof(srcMacStr));
        Mac2String(ethrHdr->ether_shost, srcMacStr, sizeof(srcMacStr) - 1);


        // If packet is an HTTP request sent by a client to the server
        // the packet is processed separately./
        if (ntohs(tcpHdrPtrParam->dport) == 80)
        {
          HandleHttpTraffic((char *)srcMacStr, ipHdrPtrParam, tcpHdrPtrParam);
        }
        else
        {
          if (tcpDataLength > 10)
          {
            ZeroMemory(tempBuffer, sizeof(tempBuffer));
            ZeroMemory(tempBuffer2, sizeof(tempBuffer2));
            ZeroMemory(data, sizeof(data));
            ZeroMemory(realData, sizeof(realData));

            /*
            * Copy connection data to data structure.
            */
            system.srcPort = ntohs(tcpHdrPtrParam->sport);
            system.dstPort = ntohs(tcpHdrPtrParam->dport);


            /*
            * Copy and stringify the payload
            */
            if (tcpDataLength > 1460)
            {
              strncpy((char *)data, (char *)tcpHdrPtrParam + tcpHeaderLength, 1460);
              stringify(data, 1460, realData);
            }
            else if (tcpDataLength > 0)
            {
              strncpy((char *)data, (char *)tcpHdrPtrParam + tcpHeaderLength, tcpDataLength);
              stringify(data, tcpDataLength, realData);
            }


            //
            if (tcpDataLength > 2)
            {
              // Write HTTP data to pipe
              if ((dataPipe = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tcpDataLength + 84)) != NULL)
              {
                // OVERHEAD is calculated as follows : 15 + 10 + 32 ~ 84
                snprintf((char *)dataPipe, tcpDataLength + 80, "TCP||%s||%s||%d||%s||%d||%s", srcMacStr, system.srcIpStr, system.srcPort, system.dstIpStr, system.dstPort, realData);
                strcat((char *)dataPipe, "\r\n");
                bufferLength = strlen((char *)dataPipe);

                WriteOutput((char *)dataPipe, bufferLength);
                HeapFree(GetProcessHeap(), 0, dataPipe);
              }
            }
          }
        }
      }
      else if (ipHdrPtrParam->proto == IP_PROTO_UDP)
      {
        totalLength = ntohs(ipHdrPtrParam->tlen);
        udpHdrPtr = (PUDPHDR)((unsigned char*)ipHdrPtrParam + ipHeaderLength);

        // Src/Dst Ports
        system.srcPort = ntohs(udpHdrPtr->sport);
        system.dstPort = ntohs(udpHdrPtr->dport);

        // Handle DNS requests.
        if (ntohs(udpHdrPtr->dport) == 53)
        {
          ZeroMemory(hostname, sizeof(hostname));
          if (GetReqHostName(packetDataParam, pcapHdrParam->len, hostname, sizeof(hostname) - 1) == OK)
          {
            // Write DNS data to pipe
            if ((dataPipe = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUF_SIZE + 1)) != NULL)
            {
              snprintf((char *)dataPipe, MAX_BUF_SIZE, "DNSREQ||%s||%s||%d||%s||%d||%s", srcMacStr, system.srcIpStr, system.srcPort, system.dstIpStr, system.dstPort, hostname);
              strcat((char *)dataPipe, "\r\n");
              bufferLength = strlen((char *)dataPipe);

              WriteOutput((char *)dataPipe, bufferLength);
              HeapFree(GetProcessHeap(), 0, dataPipe);
            }
          }
        }
        else if (ntohs(udpHdrPtr->sport) == 53)
        {
          ZeroMemory(hostname, sizeof(hostname));
          if (GetReqHostName(packetDataParam, pcapHdrParam->len, hostname, sizeof(hostname) - 1) == OK)
          {
            if ((dataPipe = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUF_SIZE + 1)) != NULL)
            {
              // We have to swap src/dst port because otherwise it won't reach the DNS request module
              snprintf((char *)dataPipe, MAX_BUF_SIZE, "DNSREP||%s||%s||%d||%s||%d||%s", srcMacStr, system.srcIpStr, system.dstPort, system.dstIpStr, system.srcPort, hostname);
              strcat((char *)dataPipe, "\r\n");
              bufferLength = strnlen((char *)dataPipe, MAX_BUF_SIZE);

              WriteOutput((char *)dataPipe, bufferLength);
              HeapFree(GetProcessHeap(), 0, dataPipe);
            }
          }

          // Generic/Dropzone traffic
        }
        else if (ntohs(udpHdrPtr->dport) == 1234 || ntohs(udpHdrPtr->sport) == 1234)
        {
          payloadPtr = ((char*)ipHdrPtrParam + ipHeaderLength + sizeof(UDPHDR));
          ZeroMemory(payload, sizeof(payload));
          CopyMemory(payload, payloadPtr, ntohs(udpHdrPtr->ulen) - sizeof(UDPHDR));
          if ((dataPipe = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUF_SIZE + 1)) != NULL)
          {
            // We have to swap src/dst port because otherwise it won't reach the DNS request module
            snprintf((char *)dataPipe, MAX_BUF_SIZE, "GENERIC||%s||%s||%d||%s||%d||%s", srcMacStr, system.srcIpStr, system.srcPort, system.dstIpStr, system.dstPort, payload);
            strcat((char *)dataPipe, "\r\n");
            bufferLength = strnlen((char *)dataPipe, MAX_BUF_SIZE);
            WriteOutput((char *)dataPipe, bufferLength);
            HeapFree(GetProcessHeap(), 0, dataPipe);

            LogMsg(2, "Generic data. (Dropzone)");
          }
        }
      }
    }
  }
}


int WriteOutput(char *pData, int pDataLen)
{
  int retVal = 0;
  DWORD dwRead = 0;

  if (pData == NULL || pDataLen <= 0)
  {
    return NOK;
  }

  EnterCriticalSection(&gCSOutputPipe);

  // Write output data to named pipe
  if (gCurrentScanParams.OutputPipeName[0] != NULL &&
    gOutputPipe != INVALID_HANDLE_VALUE &&
    gOutputPipe != 0)
  {
    if (!WriteFile(gOutputPipe, pData, pDataLen, &dwRead, NULL))
    {
      CloseHandle(gOutputPipe);
      gOutputPipe = INVALID_HANDLE_VALUE;
      LogMsg(DBG_ERROR, "WriteOutput() : Error occurred while writing \"%s\" ...", pData);
    }
    else
    {
      //LogMsg(DBG_INFO, "WriteOutput() : Data written \"%s\" ...", pData);
    }
  }
  else
  {
    // Write output data to the screen
    LogMsg(DBG_HIGH, "gOutputPipe == INVALID_HANDLE_VALUE || gOutputPipe == 0\n");
    LogMsg(DBG_HIGH, "gCurrentScanParams.OutputPipeName[0]=%s\n", gCurrentScanParams.OutputPipeName[0]);

    printf(pData);
  }

  LeaveCriticalSection(&gCSOutputPipe);

  return OK;
}



void HandleHttpTraffic(char *srcMacStrParam, PIPHDR ipHdrPtrParam, PTCPHDR tcpHdrPtrParam)
{
  char srcIpStr[MAX_BUF_SIZE + 1];
  char dstIpStr[MAX_BUF_SIZE + 1];
  char connectionId[MAX_BUF_SIZE + 1];
  char data[1500 + 1];
  char realData[1500 + 1];
  unsigned short srcPort = 0;
  unsigned short dstPort = 0;
  unsigned long sequenceNr = 0;
  unsigned long sequenceAckNr = 0;
  int numberConnections = 0;
  int ipHeaderLength = 0;
  int tcpHeaderLength = 0;
  int tcpDataLength = 0;
  int totalLength = 0;
  PCONNODE tmpNodePtr = NULL;

  ipHeaderLength = (ipHdrPtrParam->ver_ihl & 0xf) * 4;
  totalLength = ntohs(ipHdrPtrParam->tlen);
  tcpHdrPtrParam = (PTCPHDR)((u_char*)ipHdrPtrParam + ipHeaderLength);

  tcpHeaderLength = tcpHdrPtrParam->doff * 4;
  tcpDataLength = totalLength - ipHeaderLength - tcpHeaderLength;

  ZeroMemory(srcIpStr, sizeof(srcIpStr));
  ZeroMemory(dstIpStr, sizeof(dstIpStr));
  ZeroMemory(connectionId, sizeof(connectionId));

  srcPort = ntohs(tcpHdrPtrParam->sport);
  dstPort = ntohs(tcpHdrPtrParam->dport);

  snprintf(dstIpStr, sizeof(dstIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->daddr.byte1,
    ipHdrPtrParam->daddr.byte2, ipHdrPtrParam->daddr.byte3, ipHdrPtrParam->daddr.byte4);

  snprintf(srcIpStr, sizeof(srcIpStr) - 1, "%d.%d.%d.%d", ipHdrPtrParam->saddr.byte1,
    ipHdrPtrParam->saddr.byte2, ipHdrPtrParam->saddr.byte3, ipHdrPtrParam->saddr.byte4);

  sequenceNr = ntohl(tcpHdrPtrParam->seq);
  sequenceAckNr = ntohl(tcpHdrPtrParam->ack_seq);


  snprintf(connectionId, sizeof(connectionId) - 1, "%s:%d->%s:%d", srcIpStr, srcPort, dstIpStr, dstPort);

  // The data is attached to the connection buffer.
  if (tcpDataLength > 0)
  {
    ZeroMemory(data, sizeof(data));
    ZeroMemory(realData, sizeof(realData));

    // Copy and stringify the payload
    if (tcpDataLength > MAX_PAYLOAD)
    {
      strncpy(data, (char *)tcpHdrPtrParam + tcpHeaderLength, MAX_PAYLOAD);
      stringify((unsigned char *)data, MAX_PAYLOAD, (unsigned char *)realData);
    }
    else if (tcpDataLength > 0)
    {
      strncpy(data, (char *)tcpHdrPtrParam + tcpHeaderLength, tcpDataLength);
      stringify((unsigned char *)data, tcpDataLength, (unsigned char *)realData);
    }

    //Archive packet
    if (ConnectionNodeExists(gConnectionList, connectionId) == NULL)
    {
      AddConnectionToList(&gConnectionList, srcMacStrParam, srcIpStr, srcPort, dstIpStr, dstPort);
    }

    if ((tmpNodePtr = ConnectionNodeExists(gConnectionList, connectionId)) != NULL)
    {
      ConnectionAddData(tmpNodePtr, realData, strlen(realData));
    }
  }

  numberConnections = ConnectionCountNodes(gConnectionList);

  printf("HTTP  Con# : %d\n", numberConnections);

  // TCP status bits FIN or RST are set. Remove the
  // according list entries.
  if (tcpHdrPtrParam->fin == 1 || tcpHdrPtrParam->rst == 1)
  {
    ConnectionDeleteNode(&gConnectionList, connectionId);
  }

  // There should be a better place where this 
  // function is called.
  RemoveOldConnections(&gConnectionList);
}

