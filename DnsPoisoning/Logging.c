#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "DnsPoisoning.h"
#include "Logging.h"


char *gLogPriority[] = { "OFF", "DEBUG", "INFO", "LOW", "MEDIUM", "HIGH", "ERROR", "FATAL" };

char *logMutexName = "logging.mtx2";
HANDLE loggingMutex = INVALID_HANDLE_VALUE;
HANDLE fileHandle = INVALID_HANDLE_VALUE;


BOOLEAN InitLogging()
{
  if ((loggingMutex = CreateMutex(NULL, FALSE, logMutexName) == NULL) ||
    loggingMutex == ERROR_ACCESS_DENIED)
  {
    printf("InitLogging(): Creating Logging mutex failed: Error no=%d\r\n", GetLastError());
    return FALSE;
  }

  if (fileHandle = CreateFile(DBG_LOGFILE, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0) == INVALID_HANDLE_VALUE)
  {
    printf("InitLogging(): Creating file handle failed: Error no=%d\r\n", GetLastError());
    return FALSE;
  }

  printf("InitLogging(): Mutex handle (%s/%d) and logfile handle (%d) created successfully\r\n", logMutexName, loggingMutex, fileHandle);
  return TRUE;
}


void StopLogging()
{
  if (loggingMutex != INVALID_HANDLE_VALUE)
  {
    CloseHandle(loggingMutex);
  }

  if (fileHandle != INVALID_HANDLE_VALUE)
  {
    CloseHandle(fileHandle);
  }
}


void LogMsg(int priorityParam, char *logMessageParam, ...)
{
  va_list args;
  char tempBuffer[MAX_BUF_SIZE + 1];
  char logMessage[MAX_BUF_SIZE + 1];
  DWORD waitResult = -1;
  char time[MAX_BUF_SIZE + 1];

  if (priorityParam < DEBUG_LEVEL ||
      logMessageParam == NULL)
  {
    goto END;
  }

  // Remove trailing \n
  while (logMessageParam[strlen(logMessageParam) - 1] == '\n' ||
         logMessageParam[strlen(logMessageParam) - 1] == '\r')
  {
    logMessageParam[strlen(logMessageParam) - 1] = 0;
  }

  ZeroMemory(tempBuffer, sizeof(tempBuffer));
  ZeroMemory(logMessage, sizeof(logMessage));
  va_start(args, logMessageParam);
  vsprintf(tempBuffer, logMessageParam, args);
  va_end(args);
  //  snprintf(logMessage, sizeof(logMessage) - 1, "%s %-7s: %s\r\n", time, gLogPriority[priorityParam], tempBuffer);
  snprintf(logMessage, sizeof(logMessage) - 1, "%-7s: %s\r\n", gLogPriority[priorityParam], tempBuffer);
  WriteToLogfile(logMessage);

  return;

  // For what reason ever the Mutex approach
  // does not work! Must be fixed later. Any help
  // is appreciated!

  waitResult = WaitForSingleObject(loggingMutex, 1000);
  switch (waitResult)
  {
  case WAIT_FAILED:
    printf("LogMsg(): Error! Opening logging mutex (%d) failed with error no. %d\r\n", loggingMutex, GetLastError());
    break;

  case WAIT_TIMEOUT:
    printf("LogMsg(): Error! Waiting for mutex ended in timeout\r\n");
    break;

  case WAIT_OBJECT_0:
    __try
    {
      ZeroMemory(tempBuffer, sizeof(tempBuffer));
      ZeroMemory(logMessage, sizeof(logMessage));
      va_start(args, logMessageParam);
      vsprintf(tempBuffer, logMessageParam, args);
      va_end(args);
      snprintf(logMessage, sizeof(logMessage) - 1, "%s %-7s: %s\r\n", time, gLogPriority[priorityParam], tempBuffer);
      WriteToLogfile(logMessage);
    }
    __finally
    {
      if (ReleaseMutex(loggingMutex) == FALSE)
      {
        printf("LogMsg(): Error! Releasing Mutex failed with error no. %d\r\n", GetLastError());
      }
    }
    break;

  default:
    printf("LogMsg(): Error! OMG BUG!\r\n");
    break;
  }

END:

  return;
}


void WriteToLogfile(char *logMessage)
{
  char dateStamp[MAX_BUF_SIZE + 1];
  char timeStamp[MAX_BUF_SIZE + 1];
  char time[MAX_BUF_SIZE + 1];
  DWORD bytesWritten = 0;

  ZeroMemory(time, sizeof(time));
  ZeroMemory(timeStamp, sizeof(timeStamp));
  ZeroMemory(dateStamp, sizeof(dateStamp));

  // Create timestamp
  _strtime(timeStamp);
  _strdate(dateStamp);
  snprintf(time, sizeof(time) - 1, "%s %s", dateStamp, timeStamp);

  printf(logMessage);

  // Write message to the logfile.
  SetFilePointer(fileHandle, 0, NULL, FILE_END);
  WriteFile(fileHandle, logMessage, strnlen(logMessage, sizeof(logMessage) - 1), &bytesWritten, NULL);
}
