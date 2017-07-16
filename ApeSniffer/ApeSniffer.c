#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "APESniffer.h"
#include "LinkedListConnections.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "IPHLPAPI.lib")

/*
 * Extern variables
 *
 */
extern char *optarg;


/*
 * Global variables
 *
 */

CRITICAL_SECTION csSystemsLL;
CRITICAL_SECTION gCSOutputPipe;
CRITICAL_SECTION gCSConnectionsList;
PCONNODE gConnectionList = NULL;

int gDEBUGLEVEL = DEBUG_LEVEL;
SCANPARAMS gScanParams;

int gExitProcess = NOK;
char **gARGV = NULL;


int main(int argc, char* argv[])
{
  int retVal = 0;
  int opt = 0;
  int action = 0;


  // Initialisation
  if (!InitializeCriticalSectionAndSpinCount(&csSystemsLL, 0x00000400) ||
    !InitializeCriticalSectionAndSpinCount(&gCSOutputPipe, 0x00000400) ||
    !InitializeCriticalSectionAndSpinCount(&gCSConnectionsList, 0x00000400))
  {
    retVal = 1;
    goto END;
  }

  LogMsg(DBG_LOW, "main() : Starting %s", argv[0]);
  ZeroMemory(&gScanParams, sizeof(gScanParams));
  gARGV = argv;
  gConnectionList = InitConnectionList();

  // Parse command line parameters
  while ((opt = getopt(argc, argv, "lg:p:s:")) != -1)
  {
    switch (opt)
    {
      case 'g':
        strncpy(gScanParams.IFCName, optarg, sizeof(gScanParams.IFCName) - 1);
        action = 'g';
        break;
      case 'l':
        action = 'l';
        break;
      case 'p':
        strncpy(gScanParams.OutputPipeName, optarg, sizeof(gScanParams.OutputPipeName) - 1);
        break;
      case 's':
        strncpy((char *)gScanParams.IFCName, optarg, sizeof(gScanParams.IFCName));
        GetInterfaceName(optarg, (char *)gScanParams.IFCName, sizeof(gScanParams.IFCName) - 1);
        GetInterfaceDetails(optarg, &gScanParams);
        action = 's';
        break;
    }
  }


  // List all interfaces
  if (action == 'l')
  {
    ListInterfaceDetails();
    goto END;


    /*
     * General sniffer mode
     * -g IFC-Name "PCAP_Pattern"
     */
  }
  else if (argc >= 3 && action == 'g')
  {
    strncpy((char *)gScanParams.IFCName, argv[2], sizeof(gScanParams.IFCName));
    GetInterfaceName(argv[2], (char *)gScanParams.IFCName, sizeof(gScanParams.IFCName) - 1);
    GetInterfaceDetails(argv[2], &gScanParams);

    if (argv[3] != NULL)
      gScanParams.PcapPattern = (unsigned char *)argv[3];

    GenericSniffer(&gScanParams);
    goto END;


    /*
     * Start sniffer
     * -s IFC-Name
     */
  }
  else if (argc >= 3 && action == 's')
  {
    // Interface name

    StartSniffAndEvaluate(&gScanParams);

    while (1 == 1)
    {
      Sleep(1000);
      printf(".");
    }
    goto END;

  }
  else
  {
    PrintUsage(argv[0]);
  }

END:

  return 0;
}



void stringify(unsigned char *inputParam, int inputLengthParam, unsigned char *outputParam)
{
  int counter = 0;

  if (inputParam == NULL || outputParam == NULL)
  {
    return;
  }

  for (; counter < inputLengthParam && inputParam[counter] != '\0'; counter++)
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


void LogMsg(int priorityParam, char *messageParam, ...)
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


  if (priorityParam < DEBUG_LEVEL || DEBUG_LEVEL == DBG_OFF)
  {
    return;
  }

  if ((fileHandle = CreateFile(DBG_LOGFILE, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE)
  {
    return;
  }

  ZeroMemory(&overlapped, sizeof(overlapped));

  if (LockFileEx(fileHandle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0, 0, &overlapped) == FALSE)
  {
    return;
  }

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
  va_start(args, messageParam);
  vsprintf(tempBuffer, messageParam, args);
  va_end(args);
  snprintf(logMessage, sizeof(logMessage) - 1, "%s : %s\n", time, tempBuffer);
  printf(logMessage);

  // Write message to the logfile.
  SetFilePointer(fileHandle, 0, NULL, FILE_END);
  WriteFile(fileHandle, logMessage, strnlen(logMessage, sizeof(logMessage) - 1), &bytesWritten, NULL);
  UnlockFileEx(fileHandle, 0, 0, 0, &overlapped);

  CloseHandle(fileHandle);
}



void ExecCommand(char *commandParam)
{
  STARTUPINFO startupInfoParam;
  PROCESS_INFORMATION processInfoParam;
  char tempBuffer[MAX_BUF_SIZE + 1];
  char *comspec = getenv("COMSPEC");

  // Build command string + execute it.
  if (commandParam == NULL)
  {
    return;
  }

  ZeroMemory(&startupInfoParam, sizeof(startupInfoParam));
  ZeroMemory(&processInfoParam, sizeof(processInfoParam));
  ZeroMemory(tempBuffer, sizeof(tempBuffer));

  comspec = comspec != NULL ? comspec : "cmd.exe";

  startupInfoParam.cb = sizeof(STARTUPINFO);
  startupInfoParam.dwFlags = STARTF_USESHOWWINDOW;
  startupInfoParam.wShowWindow = SW_HIDE;

  snprintf(tempBuffer, sizeof(tempBuffer) - 1, "%s /c %s", comspec, commandParam);
  LogMsg(DBG_INFO, "ExecCommand() : %s", tempBuffer);

  CreateProcess(NULL, tempBuffer, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfoParam, &processInfoParam);
}



/*
 *
 *
 */
void PrintUsage(char *pAppName)
{
  system("cls");
  printf("\nAPESniffer  Version %s\n", APESNIFFER_VERSION);
  printf("-----------------------\n\n");
  printf("List all interfaces               :  %s -l\n", pAppName);
  printf("Start generic sniffer             :  %s -g IFC-Name\n", pAppName);
  printf("Start APE sniffer                 :  %s -s IFC-Name [-p PIPE_NAME] \n", pAppName);
  printf("\n\n\n\nExamples\n--------\n\n");
  printf("Example : %s -l\n", pAppName);
  printf("Example : %s -x 0F716AAF-D4A7-ACBA-1234-EA45A939F624\n", pAppName);
  printf("Example : %s -g 0F716AAF-D4A7-ACBA-1234-EA45A939F624\n\n\n\n\n", pAppName);
  printf("WinPcap version\n---------------\n\n");
  printf("%s\n\n", pcap_lib_version());
}

