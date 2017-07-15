#pragma once


#define DEBUG_LEVEL 1

#define DBG_OFF    0
#define DBG_INFO   1
#define DBG_LOW    2
#define DBG_MEDIUM 3
#define DBG_HIGH   4
#define DBG_ALERT  5
#define DBG_ERROR  5

#define DBG_LOGFILE "c:\\debug.log"


void LogMsg(int priorityParam, char *logMessageParam, ...);