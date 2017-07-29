#pragma once

#include "ApeSniffer.h"

int ListInterfaceDetails();
int GetInterfaceDetails(char *ifcName, PSCANPARAMS scanParams);
int GetInterfaceName(char *ifcName, char *realIfcName, int bufferSize);
