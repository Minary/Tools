#pragma once

#include "RouterIPv4.h"


int InitializeParsePcapDumpFile();
BOOL OpenPcapFileHandle(PSCANPARAMS scanParams);
BOOL OpenPcapInterfaceHandle(PSCANPARAMS scanParams);
