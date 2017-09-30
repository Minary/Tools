#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "APESniffer.h"
#include "Logging.h"

char *gLogPriority[] = { "OFF", "DEBUG", "INFO", "LOW", "MEDIUM", "HIGH", "ERROR", "FATAL" };


static HANDLE fileHandle = INVALID_HANDLE_VALUE;
void LogMsg(int priorityParam, char *logMessageParam, ...)
{
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
    goto END;
  }

  if (fileHandle == INVALID_HANDLE_VALUE &&
      (fileHandle = CreateFile(DBG_LOGFILE, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE)
  {
    goto END;
  }

  ZeroMemory(&overlapped, sizeof(overlapped));
  if (LockFileEx(fileHandle, LOCKFILE_EXCLUSIVE_LOCK, 0, 0, 0, &overlapped) == TRUE)
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
  PrintToScreen(logMessage);

  // Write message to the logfile.
  SetFilePointer(fileHandle, 0, NULL, FILE_END);
//  WriteFile(fileHandle, logMessage, strnlen(logMessage, sizeof(logMessage) - 1), &bytesWritten, NULL);

END:
  if (fileHandle != INVALID_HANDLE_VALUE)
  {
    UnlockFileEx(fileHandle, 0, 0, 0, &overlapped);
    CloseHandle(fileHandle);
  }
}


void PrintToScreen(char *data)
{
  if (data == NULL)
  {
    return;
  }

  __try
  {
    puts(data);
  }
  __except (filterException(GetExceptionCode(), GetExceptionInformation()))
  {
    puts("OMG it's a bug!!\r\n");
  }
}
