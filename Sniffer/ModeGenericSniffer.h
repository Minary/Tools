#pragma once

#include <windows.h>
#include "Sniffer.h"

int ModeGenericSnifferStart(PSCANPARAMS pScanParams);
void GenericSnifferCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
