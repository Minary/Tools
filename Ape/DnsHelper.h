#pragma once

unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count);
void hexdump(void *mem, unsigned int len);
void ChangeToDnsNameFormat(unsigned char* dns, unsigned char* host);
