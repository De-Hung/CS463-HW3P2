#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

#define MAGIC_PORT 22345
// max UDP packet size
#define MAX_PKT_SIZE (1500 - 28)

// possible status codes from ss.Open, ss.Send, ss.Close
#define STATUS_OK          0   // no error
#define ALREADY_CONNECTED  1   // second call to ss.Open() without closing connection
#define NOT_CONNECTED      2   // call to ss.Send()/Close() without ss.Open()
#define INVALID_NAME       3   // ss.Open() with targetHost that has no DNS entry
#define FAILED_SEND        4   // sendto() failed in kernel
#define TIMEOUT            5   // timeout after all retx attempts are exhausted
#define FAILED_RECV        6   // recvfrom() failed in kernel

#define FORWARD_PATH 0
#define RETURN_PATH  1

#define MAGIC_PROTOCOL 0x8311AA
#define SYN_MAX_ATTEMPTS   3
#define OTHER_MAX_ATTEMPTS 5
#define DEFAULT_RTO        1.0

#pragma pack(push, 1)

class Flags {
public:
    DWORD reserved : 5;     // must be 0
    DWORD SYN : 1;
    DWORD ACK : 1;
    DWORD FIN : 1;
    DWORD magic : 24;
    Flags() { memset(this, 0, sizeof(*this)); magic = MAGIC_PROTOCOL; }
};

class SenderDataHeader {
public:
    Flags flags;
    DWORD seq;      // must begin from 0
};

class LinkProperties {
public:
    float RTT;            // propagation RTT (in sec)
    float speed;          // bottleneck bandwidth (in bits/sec)
    float pLoss[2];       // probability of loss in each direction
    DWORD bufferSize;     // buffer size of emulated routers (in packets)
    LinkProperties() { memset(this, 0, sizeof(*this)); }
};

class SenderSynHeader {
public:
    SenderDataHeader sdh;
    LinkProperties lp;
};

class ReceiverHeader {
public:
    Flags flags;
    DWORD recvWnd;        // receiver window for flow control (in pkts)
    DWORD ackSeq;         // ack value = next expected sequence
};

#pragma pack(pop)

class SenderSocket {
public:
    SenderSocket();
    ~SenderSocket();

    int Open(const char* targetHost, int port, int senderWindow, LinkProperties* lp);
    int Send(const char* buf, int bytes);   // stub in Part 1
    int Close();

private:
    // sends pkt, waits up to RTO for a reply with expected flags
    // success fills rh and rtt
    int SendAndWait(const char* name, DWORD seq, const char* pkt, int len, int maxAttempts, bool printIP, bool wantSYN, bool wantFIN, ReceiverHeader& rh, double& rtt);
    double Now() const;   // seconds since constructor

    SOCKET sock;
    struct sockaddr_in server;
    bool connected;
    double RTO;
    DWORD nextSeq;
    std::chrono::steady_clock::time_point t0;
};
