#pragma once

#include "APE.h"


void PrintConfig(SCANPARAMS scanParamsParam);
int ParseTargetHostsConfigFile(char *targetsFile);
int ParseDnsPoisoningConfigFile(char *pConfigFile);
