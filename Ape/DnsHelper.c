#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "DnsHelper.h"
#include "DnsStructs.h"
#include "LinkedListSpoofedDnsHosts.h"
#include "NetworkStructs.h"


// convert 3www6google3com0 to www.google.com\0
unsigned char* ChangeDnsNameToTextFormat(unsigned char* reader, unsigned char* buffer, int* count)
{
  unsigned char *name;
  unsigned int p = 0, jumped = 0, offset;
  int i, j;

  *count = 1;
  name = (unsigned char*)malloc(256);
  name[0] = '\0';

  //read the names in 3www6google3com format
  while (*reader != 0)
  {
    if (*reader >= 192)
    {
      offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }
    else
    {
      name[p++] = *reader;
    }

    reader = reader + 1;

    if (jumped == 0) *count = *count + 1; //if we havent jumped to another location then we can count up
  }

  name[p] = '\0'; //string complete
  if (jumped == 1)
  {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }

  //now convert 3www6google3com0 to www.google.com
  for (i = 0; i < (int)strlen((const char*)name); i++)
  {
    p = name[i];
    for (j = 0; j < (int)p; j++)
    {
      name[i] = name[i + 1];
      i = i + 1;
    }
    name[i] = '.';
  }

  name[i - 1] = '\0'; //remove the last dot

  return name;
}


// convert www.google.com\0 to 3www6google3com0
void ChangeTextToDnsNameFormat(unsigned char* dns, unsigned char* host)
{
  unsigned int lock = 0;
  unsigned int i = 0;
  strcat((char*)host, ".");

  for (; i < strlen((char*)host); i++)
  {
    if (host[i] == '.')
    {
      *dns++ = i - lock;

      for (; lock < i; lock++)
      {
        *dns++ = host[lock];
      }

      lock++; //or lock=i+1;
    }
  }

  *dns++ = '\0';
}

