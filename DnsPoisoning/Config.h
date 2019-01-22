#pragma once

#include "DnsPoisoning.h"


void PrintConfig(SCANPARAMS scanParamsParam);
int ParseDnsPoisoningConfigFile(char *pConfigFile);
int ParseTargetHostsConfigFile(char *targetsFile);
