#pragma once
#include <windows.h>

class Checksum {
public:
    Checksum();
    DWORD CRC32(const unsigned char* buf, size_t len);

private:
    DWORD crc_table[256];
};