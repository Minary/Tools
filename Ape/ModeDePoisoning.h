#pragma once

void InitializeDePoisoning();
void StartUnpoisoningProcess();
void WriteDepoisoningFile(void);
void ExecCommand(char *commandParam);
DWORD WINAPI ArpDePoisoning(LPVOID scanParamsParam);