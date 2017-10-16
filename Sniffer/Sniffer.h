#ifndef __SNIFFER__
#define __SNIFFER__

#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include "NetBase.h"


#define SNIFFER_VERSION "0.1"
#define DBG_LOGFILE "c:\\debug.log"


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
  unsigned char IfcName[MAX_BUF_SIZE + 1];
  unsigned char IfcAlias[MAX_BUF_SIZE + 1];
  unsigned char IfcDescr[MAX_BUF_SIZE + 1];
  int Index;
  unsigned char GWIP[BIN_IP_LEN];
  unsigned char GWIPStr[MAX_IP_LEN];
  unsigned char GWMAC[BIN_MAC_LEN];
  unsigned char GWMACStr[MAX_MAC_LEN];
  unsigned char StartIP[BIN_IP_LEN];
  unsigned long StartIPNum;
  unsigned char StopIP[BIN_IP_LEN];
  unsigned long StopIPNum;
  unsigned char LocalIP[BIN_IP_LEN];
  unsigned char LocalIPStr[MAX_IP_LEN];
  unsigned char LocalMAC[BIN_MAC_LEN];
  unsigned char LocalMACStr[MAX_MAC_LEN];
  unsigned char *PcapPattern;
  unsigned char OutputPipeName[MAX_BUF_SIZE + 1];
  HANDLE PipeHandle;
  void *IfcReadHandle;  // HACK! because of header hell :/
  void *IfcWriteHandle; // HACK! because of header hell :/
} SCANPARAMS, *PSCANPARAMS;



/*
 * Function forward declarations.
 *
 */
void stringify(unsigned char *pInput, int pInputLen, unsigned char *pOutput);
void ExecCommand(char *pCmd);
void PrintConfig(SCANPARAMS pScanParams);
int UserIsAdmin();
void PrintUsage(char *pAppName);

#endif

