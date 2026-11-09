#include "SenderSocket.h"
#include <stdio.h>

// initialize socket
SenderSocket::SenderSocket() : sock(INVALID_SOCKET), connected(false), RTO(DEFAULT_RTO), nextSeq(0) {
    memset(&server, 0, sizeof(server));
    t0 = std::chrono::steady_clock::now();
}

SenderSocket::~SenderSocket() {
    if (sock != INVALID_SOCKET)
        closesocket(sock);
}

// if program exits prematurely
double SenderSocket::Now() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

int SenderSocket::Open(const char* targetHost, int port, int senderWindow, LinkProperties* lp) {
    if (connected) return ALREADY_CONNECTED;

    // builds destination address
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)port);

    // takes in the string as an IP
    DWORD ip = inet_addr(targetHost);
    if (ip == INADDR_NONE) {
        struct hostent* remote = gethostbyname(targetHost);
        if (remote == NULL) {
            printf("[%6.3f]\t--> target %s is invalid\n", Now(), targetHost);
            return INVALID_NAME;
        }
        memcpy(&server.sin_addr, remote->h_addr, remote->h_length);
    } else {
        server.sin_addr.S_un.S_addr = ip;
    }

    // create and bind UDP socket to port 0
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("[%6.3f]\t--> failed socket with %d\n", Now(), WSAGetLastError());
        return FAILED_SEND;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        printf("[%6.3f]\t--> failed bind with %d\n", Now(), WSAGetLastError());
        closesocket(sock);
        sock = INVALID_SOCKET;
        return FAILED_SEND;
    }

    // SYN
    // router buffer
    lp->bufferSize = senderWindow + OTHER_MAX_ATTEMPTS;
    SenderSynHeader ssh;
    ssh.sdh.flags.SYN = 1;
    ssh.sdh.seq = 0;
    ssh.lp = *lp;

    ReceiverHeader rh;
    double rtt = 0;
    int status = SendAndWait("SYN", 0, (const char*)&ssh, sizeof(ssh), SYN_MAX_ATTEMPTS, true, true, false, rh, rtt);
    if (status != STATUS_OK) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        return status;
    }

    // SYN-ACK
    RTO = 3.0 * rtt;
    printf("[%6.3f]\t<-- SYN-ACK %d window %d; setting initial RTO to %.3f\n", Now(), rh.ackSeq, rh.recvWnd, RTO);

    nextSeq = 0;
    connected = true;
    return STATUS_OK;
}

int SenderSocket::Send(const char* buf, int bytes) {
    // Placeholder for main
    if (!connected) return NOT_CONNECTED;
    return STATUS_OK;
}

int SenderSocket::Close() {
    if (!connected) return NOT_CONNECTED;

    SenderDataHeader sdh;
    sdh.flags.FIN = 1;
    sdh.seq = nextSeq;

    ReceiverHeader rh;
    double rtt = 0;
    int status = SendAndWait("FIN", nextSeq, (const char*)&sdh, sizeof(sdh), OTHER_MAX_ATTEMPTS, false, false, true, rh, rtt);
    if (status != STATUS_OK) return status;

    printf("[%6.3f]\t<-- FIN-ACK %d window %d\n", Now(), rh.ackSeq, rh.recvWnd);
    connected = false;
    closesocket(sock);
    sock = INVALID_SOCKET;
    return STATUS_OK;
}

int SenderSocket::SendAndWait(const char* name, DWORD seq, const char* pkt, int len, int maxAttempts, bool printIP, bool wantSYN, bool wantFIN, ReceiverHeader& rh, double& rtt) {
    // records when attempt was sent
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        double sendTime = Now();

        if (printIP) printf("[%6.3f]\t--> %s %d (attempt %d of %d, RTO %.3f) to %s\n", sendTime, name, seq, attempt, maxAttempts, RTO, inet_ntoa(server.sin_addr));
        else printf("[%6.3f]\t--> %s %d (attempt %d of %d, RTO %.3f)\n", sendTime, name, seq, attempt, maxAttempts, RTO);

        if (sendto(sock, pkt, len, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            printf("[%6.3f]\t--> failed sendto with %d\n", Now(), WSAGetLastError());
            return FAILED_SEND;
        }

        double deadline = sendTime + RTO;

        // wait for a matching reply until RTO expires
        while (true) {
            double remaining = deadline - Now();
            if (remaining <= 0) break;

            fd_set fd;
            FD_ZERO(&fd);
            FD_SET(sock, &fd);
            timeval tv;
            tv.tv_sec = (long)remaining;
            tv.tv_usec = (long)((remaining - tv.tv_sec) * 1e6);

            int ready = select(0, &fd, NULL, NULL, &tv);
            if (ready == SOCKET_ERROR) {
                printf("[%6.3f]\t<-- failed recvfrom with %d\n", Now(), WSAGetLastError());
                return FAILED_RECV;
            }
            if (ready == 0) break;

            struct sockaddr_in from;
            int fromLen = sizeof(from);
            int bytes = recvfrom(sock, (char*)&rh, sizeof(rh), 0, (struct sockaddr*)&from, &fromLen);

            if (bytes == SOCKET_ERROR) {
                printf("[%6.3f]\t<-- failed recvfrom with %d\n", Now(), WSAGetLastError());
                return FAILED_RECV;
            }
            if (bytes != sizeof(ReceiverHeader)) continue;
            if (rh.flags.ACK && ((wantSYN && rh.flags.SYN) || (wantFIN && rh.flags.FIN))) {
                rtt = Now() - sendTime;
                return STATUS_OK;
            }
            // otherwise ignore and keep waiting out RTO
        }
    }
    return TIMEOUT;
}
