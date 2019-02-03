#pragma once

#include "RouterIPv4.h"


void PrintConfig(SCANPARAMS scanParamsParam);
int ParseTargetHostsConfigFile(char *targetsFile);
int ParseDnsPoisoningConfigFile(char *pConfigFile);
int ParseFirewallConfigFile(char *firewallRulesFile);