#ifndef __ARPPOISONINGENGINE__
#define __ARPPOISONINGENGINE__

#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include "NetBase.h"


#define APE_VERSION "0.15"

#define WITH_HTTP_INJECTION 0
#define WITH_DNS_SPOOFER 0
#define WITH_FIREWALL 0
#define WITH_SNIFFER 0

#define DEBUG_LEVEL 0

#define DBG_OFF    0
#define DBG_INFO   1
#define DBG_LOW    2
#define DBG_MEDIUM 3
#define DBG_HIGH   4
#define DBG_ALERT  5
#define DBG_ERROR  5


#define FILE_HOST_TARGETS ".targethosts"
#define FILE_FIREWALL_RULES1 ".fwrules"
#define FILE_FIREWALL_RULES2 "bin\\.fwrules"
#define FILE_DNS_POISONING ".dnshosts"
#define FILE_HTTPINJECTION_RULES1 ".injecturls"
#define FILE_HTTPINJECTION_RULES2 "bin\\.injecturls"
#define FILE_UNPOISON ".UNPOISON"
#define DBG_LOGFILE "c:\\debug.log"
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
  unsigned char interfaceName[MAX_BUF_SIZE + 1];
  unsigned char interfaceAlias[MAX_BUF_SIZE + 1];
  unsigned char interfaceDescr[MAX_BUF_SIZE + 1];
  int index;
  unsigned char gatewayIpBin[BIN_IP_LEN];
  unsigned char gatewayIpStr[MAX_IP_LEN];
  unsigned char gatewayMacBin[BIN_MAC_LEN];
  unsigned char gatewayMacStr[MAX_MAC_LEN];
  unsigned char startIpBin[BIN_IP_LEN];
  unsigned long startIpNum;
  unsigned char stopIpBin[BIN_IP_LEN];
  unsigned long stopIpNum;
  unsigned char localIpBin[BIN_IP_LEN];
  unsigned char localIpStr[MAX_IP_LEN];
  unsigned char localMacBin[BIN_MAC_LEN];
  unsigned char localMacStr[MAX_MAC_LEN];
  unsigned char *PCAPPattern;
  unsigned char OutputPipeName[MAX_BUF_SIZE + 1];
  HANDLE PipeHandle;
  void *interfaceReadHandle;  // HACK! because of header hell :/
  void *interfaceWriteHandle; // HACK! because of header hell :/
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

#endif

