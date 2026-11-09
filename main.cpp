#include "SenderSocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>

// if params are incorrect
static void Usage() {
    printf("Must be in Usage format: hw3p1.exe <host> <power> <senderWindow> <RTT> <lossFwd> <lossRet> <speedMbps>\n");
}

int main(int argc, char** argv) {
    if (argc != 8) {
        Usage();
        return -1;
    }

    char* targetHost = argv[1];
    int power = atoi(argv[2]);
    int senderWindow = atoi(argv[3]);

    // max power of 30, can change
    if (power < 1 || power > 30 || senderWindow < 1) {
        Usage();
        return -1;
    }

    // Link properties
    LinkProperties lp;
    lp.RTT = (float)atof(argv[4]);
    lp.pLoss[FORWARD_PATH] = (float)atof(argv[5]);
    lp.pLoss[RETURN_PATH] = (float)atof(argv[6]);
    // Mbps -> bps
    lp.speed = 1e6f * (float)atof(argv[7]);
    if (lp.speed <= 0 || lp.RTT < 0) {
        Usage();
        return -1;
    }

    printf("Main:\tsender W = %d, RTT %.3f sec, loss %g / %g, link %g Mbps\n", senderWindow, lp.RTT, lp.pLoss[FORWARD_PATH], lp.pLoss[RETURN_PATH], atof(argv[7]));

    // Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup error %d\n", WSAGetLastError());
        return -1;
    }

    // buffer initialized
    printf("Main:\tinitializing DWORD array with 2^%d elements... ", power);
    auto tInit = std::chrono::steady_clock::now();

    UINT64 dwordBufSize = (UINT64)1 << power;
    DWORD* dwordBuf = new DWORD[dwordBufSize];
    for (UINT64 i = 0; i < dwordBufSize; i++) dwordBuf[i] = (DWORD)i;

    int initMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tInit).count();
    printf("done in %d ms\n", initMs);

    // connect
    SenderSocket ss;
    int status;
    auto tOpen = std::chrono::steady_clock::now();
    if ((status = ss.Open(targetHost, MAGIC_PORT, senderWindow, &lp)) != STATUS_OK) {
        printf("Main:\tconnect failed with status %d\n", status);
        delete[] dwordBuf;
        WSACleanup();
        return -1;
    }
    auto tConnected = std::chrono::steady_clock::now();
    printf("Main:\tconnected to %s in %.3f sec, pkt size %d bytes\n", targetHost, std::chrono::duration<double>(tConnected - tOpen).count(), MAX_PKT_SIZE);

    // transfer
    char* charBuf = (char*)dwordBuf;
    UINT64 byteBufferSize = dwordBufSize << 2;
    UINT64 off = 0;

    while (off < byteBufferSize) {
        int bytes = (int)std::min<UINT64>(byteBufferSize - off, MAX_PKT_SIZE - sizeof(SenderDataHeader));
        if ((status = ss.Send(charBuf + off, bytes)) != STATUS_OK) {
            printf("Main:\tsend failed with status %d\n", status);
            delete[] dwordBuf;
            WSACleanup();
            return -1;
        }
        off += bytes;
    }

    // transfer time = returning from Open() - calling Close()
    double transferTime = std::chrono::duration<double>(std::chrono::steady_clock::now() - tConnected).count();

    if ((status = ss.Close()) != STATUS_OK) {
        printf("Main:\tclose failed with status %d\n", status);
        delete[] dwordBuf;
        WSACleanup();
        return -1;
    }

    printf("Main:\ttransfer finished in %.3f sec\n", transferTime);

    // clean up
    delete[] dwordBuf;
    WSACleanup();
    return 0;
}
