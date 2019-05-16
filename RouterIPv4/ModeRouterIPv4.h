#pragma once

void InitializeRouterIPv4();
void AdminCheck(char *programNameParam);
int UserIsAdmin();
BOOL InitTargethostObserverThread();
DWORD WINAPI TargethostsObserver(LPVOID params);
