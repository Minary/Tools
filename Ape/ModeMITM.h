#pragma once

void InitializeMITM();
void AdminCheck(char *programNameParam);
int UserIsAdmin();
void ParseTargetHostsConfigFile(char *targetsFileParam);
