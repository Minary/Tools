#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "APE.h"
#include "Logging.h"


char *gLogPriority[] = { "OFF", "DEBUG", "INFO", "LOW", "MEDIUM", "HIGH", "ERROR", "FATAL" };
HANDLE loggingMutex;
static HANDLE fileHandle = INVALID_HANDLE_VALUE;


BOOLEAN InitLogging()
{
  if ((loggingMutex = CreateMutexA(NULL, FALSE, NULL) == NULL) || loggingMutex == INVALID_HANDLE_VALUE)
  {
    printf("InitLogging(): Creating Logging mutex failed: Error no=%d\n", GetLastError());
    return FALSE;
  }

  if (fileHandle = CreateFile(DBG_LOGFILE, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0) == INVALID_HANDLE_VALUE)
  {
    printf("InitLogging(): Creating file handle failed: Error no=%d\n", GetLastError());
    return FALSE;
  }

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
  char dateStamp[MAX_BUF_SIZE + 1];
  char timeStamp[MAX_BUF_SIZE + 1];
  char time[MAX_BUF_SIZE + 1];
  char tempBuffer[MAX_BUF_SIZE + 1];
  char logMessage[MAX_BUF_SIZE + 1];
  DWORD bytesWritten = 0;
  va_list args;
  DWORD waitResult = 0;

  waitResult = WaitForSingleObject(loggingMutex, 1000);
  if (waitResult == WAIT_ABANDONED)
  {
    printf("LogMsg(): Error! Mutex is abandoned\r\n");
    goto END;
  }

  if (waitResult == WAIT_FAILED)
  {
    printf("LogMsg(): Error! Opening mutex failed\r\n");
    goto END;
  }

  if (waitResult == WAIT_TIMEOUT)
  {
    printf("LogMsg(): Error! Opening mutex ran in timeout\r\n");
    goto END;
  }
  

  if (waitResult != WAIT_OBJECT_0)
  {
    printf("LogMsg(): Error! Mutex (%d) is invalid\r\n", loggingMutex);
    goto END;
  }

  if (priorityParam < DEBUG_LEVEL || DEBUG_LEVEL == DBG_OFF)
  {
    goto END;
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
  va_start(args, logMessageParam);
  vsprintf(tempBuffer, logMessageParam, args);
  va_end(args);
  snprintf(logMessage, sizeof(logMessage) - 1, "%s %-7s: %s\n", time, gLogPriority[priorityParam], tempBuffer);
  printf(logMessage);

  // Write message to the logfile.
  SetFilePointer(fileHandle, 0, NULL, FILE_END);
  WriteFile(fileHandle, logMessage, strnlen(logMessage, sizeof(logMessage) - 1), &bytesWritten, NULL);

END:
  __try
  {
    if (ReleaseMutex(loggingMutex) == FALSE)
    {
      printf("LogMsg(): Error! Releasing Mutex failed with error no. %d\r\n", GetLastError());
    }
  }
  __finally
  {
  }
}