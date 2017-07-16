#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

#include "NetworkPackets.h"


#define APE_VERSION "0.15"

#define WITH_HTTP_INJECTION 0
#define WITH_DNS_SPOOFER 0
#define WITH_FIREWALL 0
#define WITH_SNIFFER 0


#define FILE_HOST_TARGETS ".targethosts"
#define FILE_FIREWALL_RULES1 ".fwrules"
#define FILE_FIREWALL_RULES2 "bin\\.fwrules"
#define FILE_DNS_POISONING ".dnshosts"
#define FILE_HTTPINJECTION_RULES1 ".injecturls"
#define FILE_HTTPINJECTION_RULES2 "bin\\.injecturls"
#define FILE_UNPOISON ".UNPOISON"
#define HOSTS_FILE "hosts.txt"


#define TCP_MAX_ACTIVITY 10
#define MAX_ID_LEN 128
#define MAX_PAYLOAD 1460
#define MAX_CONNECTION_VOLUME 4096
#define MAX_CONNECTION_COUNT 1024

#define MAX_SYSTEMS_COUNT 1024
#define MAX_ARP_SCAN_ROUNDS 5

#define MAX_BUF_SIZE 1024
#define MAX_PACKET_SIZE 512


#define PCAP_READTIMEOUT 1

#define SLEEP_BETWEEN_ARPS 50
#define SLEEP_BETWEEN_REPOISONING 5000 // 10 secs
#define SLEEP_BETWEEN_ARPSCANS 120 * 1000 // 120 secs

#define snprintf _snprintf

#define OK 0
#define NOK 1


/*
 * Type definitions
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
void Stringify(unsigned char *inputParam, int inputLengthParam, unsigned char *outputParam);
BOOL APE_ControlHandler(DWORD idParam);
void WriteDepoisoningFile(void);
void StartUnpoisoningProcess();
void ExecCommand(char *cmd);
void LogMsg(int priorityParam, char *msgParam, ...);
void PrintConfig(SCANPARAMS scanParamsParam);
void PrintTimestamp(char *titleParam);
int UserIsAdmin();
void AdminCheck(char *programNameParam);
void PrintUsage(char *applicationNameParam);
void ParseTargetHostsConfigFile(char *targetsFileParam);
void ParseDnsConfigFile();

