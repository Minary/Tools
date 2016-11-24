
#ifndef __GSNIFFER__
#define __GSNIFFER__

#include <windows.h>


/*
 * Type definitions
 *
 */



/*
 * Function forward declarations
 *
 */
int GeneralSniffer(PSCANPARAMS pScanParams);
void GENERALSnifferCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif