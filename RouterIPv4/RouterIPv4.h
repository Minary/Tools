#pragma once

#include "NetworkStructs.h"

#define MAX_BUF_SIZE 1024
#define MAX_SYSTEMS_COUNT 1024

#define ROUTERIPV4_VERSION "0.1"
#define FILE_HOST_TARGETS ".targethosts"
#define FILE_FIREWALL_RULES ".fwrules"

#define PCAP_READTIMEOUT 1


/*
 * Type Definitions
 *
 */

typedef struct
{
  unsigned char sysIpStr[MAX_IP_LEN + 1];
  unsigned char sysIpBin[BIN_IP_LEN];
  unsigned char sysMacBin[BIN_MAC_LEN];
  unsigned char srcIpStr[MAX_IP_LEN + 1];
  unsigned char dstIpStr[MAX_IP_LEN + 1];
  unsigned short srcPort;
  unsigned short dstPort;
} SYSTEMNODE, *PSYSTEMNODE, **PPSYSTEMNODE;


typedef struct SCANPARAMS
{
  unsigned char ApplicationName[MAX_BUF_SIZE + 1];
  unsigned char InterfaceName[MAX_BUF_SIZE + 1];
  unsigned char InterfaceAlias[MAX_BUF_SIZE + 1];
  unsigned char InterfaceDescr[MAX_BUF_SIZE + 1];
  int Index;
  unsigned char GatewayIpBin[BIN_IP_LEN];
  unsigned char GatewayIpStr[MAX_IP_LEN];
  unsigned char GatewayMacBin[BIN_MAC_LEN];
  unsigned char GatewayMacStr[MAX_MAC_LEN];
  unsigned char StartIpBin[BIN_IP_LEN];
  unsigned long StartIpNum;
  unsigned char StopIpBin[BIN_IP_LEN];
  unsigned long StopIpNum;
  unsigned char LocalIpBin[BIN_IP_LEN];
  unsigned char LocalIpStr[MAX_IP_LEN];
  unsigned char LocalMacBin[BIN_MAC_LEN];
  unsigned char LocalMacStr[MAX_MAC_LEN];
  unsigned char *PcapPattern;
  unsigned char OutputPipeName[MAX_BUF_SIZE + 1];
  unsigned char PcapFilePath[MAX_BUF_SIZE + 1];
  HANDLE PipeHandle;
  void *InterfaceReadHandle;  // HACK! because of header hell :/ Anyone?
  void *InterfaceWriteHandle; // HACK! because of header hell :/ Anyone?

  void *PcapFileHandle; // HACK! because of header hell :/ Anyone?
} SCANPARAMS, *PSCANPARAMS;


/*
 * Function forward declarations.
 *
 */
void PrintUsage(char *pAppName);
int ParseDnsPoisoningConfigFile(char *configFileParam);
BOOL RouterIPv4_ControlHandler(DWORD pControlType);
void Stringify(unsigned char *inputParam, int inputLenthParam, unsigned char *outputParam);