
#ifndef __GSNIFFER__
#define __GSNIFFER__

#include <windows.h>
#include "APESniffer.h"


/*
 * Type definitions
 *
 */



/*
 * Function forward declarations
 *
 */
int GenericSniffer(PSCANPARAMS pScanParams);
void GenericSnifferCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif