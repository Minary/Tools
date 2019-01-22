#pragma once

#include "APE.h"


void PrintConfig(SCANPARAMS scanParamsParam);
int ParseTargetHostsConfigFile(char *targetsFile);
int ParseFirewallConfigFile(char *firewallRulesFile);
int ParseDnsPoisoningConfigFile(char *pConfigFile);
