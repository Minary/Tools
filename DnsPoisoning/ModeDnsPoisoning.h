#pragma once

void PrintUsage(char *pAppName);
void InitializeDP();
void AdminCheck(char *programNameParam);
int UserIsAdmin();
BOOL InitTargethostObserverThread();
DWORD WINAPI TargethostsObserver(LPVOID params);