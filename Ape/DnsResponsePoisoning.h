#ifndef __DNSRESPONSEPOISONING__
#define __DNSRESPONSEPOISONING__

/*
 * Function forward declarations
 *
 */
void *DnsResponsePoisonerGetHost2Spoof(u_char *pData);
unsigned char* dns2Text(unsigned char*, unsigned char*, int*);

#endif