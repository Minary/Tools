#pragma once

void InitializeArpMitm();
void AdminCheck(char *programNameParam);
int UserIsAdmin();
void CloseAllPcapHandles();
BOOL InitTargethostObserverThread();
DWORD WINAPI TargethostsObserver(LPVOID params);