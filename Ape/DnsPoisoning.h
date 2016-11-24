#ifndef __DNSPOISONING__
#define __DNSPOISONING__

/* 
 * Type definitions
 *
 */



/*
 * Function forward declarations
 *
 */
void ParseDNSPoisoningConfigFile(char *pConfigFile);
int DetermineSpoofingResponseData(PSCANPARAMS pParams);
DWORD WINAPI DnsResponseSniffer(LPVOID lpParam);

#endif