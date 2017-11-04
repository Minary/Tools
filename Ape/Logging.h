#pragma once


#define DEBUG_LEVEL 1

#define DBG_OFF    0
#define DBG_DEBUG  1
#define DBG_INFO   2
#define DBG_LOW    3
#define DBG_MEDIUM 4
#define DBG_HIGH   5
#define DBG_ERROR  6
#define DBG_FATAL  7

#define DBG_LOGFILE "c:\\debug.log"

BOOLEAN InitLogging();
void StopLogging();
void LogMsg(int priorityParam, char *logMessageParam, ...);
void WriteToLogfile(char *logMessage);