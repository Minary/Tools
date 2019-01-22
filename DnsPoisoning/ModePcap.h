#pragma once

#include "DnsPoisoning.h"


int InitializeParsePcapDumpFile();
BOOL OpenPcapFileHandle(PSCANPARAMS scanParams);
BOOL OpenPcapInterfaceHandle(PSCANPARAMS scanParams);
