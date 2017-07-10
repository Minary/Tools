#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "DNSHelper.h"


unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
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


//this will convert www.google.com to 3www6google3com ;got it :)
void ChangeToDnsNameFormat(unsigned char* dns, unsigned char* host)
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



#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

void hexdump(void *mem, unsigned int len)
{
  unsigned int i, j;

  for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
  {
    /* print offset */
    if (i % HEXDUMP_COLS == 0)
    {
      printf("0x%06x: ", i);
    }

    /* print hex data */
    if (i < len)
    {
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    }
    else /* end of block, just aligning for ASCII dump */
    {
      printf("   ");
    }

    /* print ASCII dump */
    if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
    {
      for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
      {
        if (j >= len) /* end of block, not really printing */
        {
          putchar(' ');
        }
        else if (isprint(((char*)mem)[j])) /* printable char */
        {
          putchar(0xFF & ((char*)mem)[j]);
        }
        else /* other char */
        {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}