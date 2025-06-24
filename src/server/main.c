// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socks5.h"
#include "util.h"

#define MAX_PENDING_CONNECTION_REQUESTS 5
#define SOURCE_PORT 1080

int main(int argc, const char* argv[]) {
    // Disable buffering on stdout and stderr
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Create the socket. We'll use IPv6 only, IPv6 has backwards compatibility with IPv4
    // so by using IPv6, we can also handle incoming IPv4 connections ;)
    int serverSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0) {
        perror("[ERR] socket()");
        exit(1);
    }

    // We want to bind our socket on IPv6 listening on all available IP addresses on port SOURCE_PORT.
    struct sockaddr_in6 srcSocket;
    memset((char*)&srcSocket, 0, sizeof(srcSocket));
    srcSocket.sin6_family = AF_INET6;
    srcSocket.sin6_port = htons(SOURCE_PORT);
    memcpy(&srcSocket.sin6_addr, &in6addr_any, sizeof(in6addr_any));

    if (bind(serverSocket, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        perror("[ERR] bind()");
        exit(1);
    }

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        perror("[ERR] listen()");
        exit(1);
    }

    // Get the local address at which our socket was found, for nothing more than printing it out.
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(serverSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Binding to %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname()");

    // Handle incomming connections
    while (1) {
        printf("Listening for next client...\n");

        struct sockaddr_storage clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);
        int clientHandleSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
        if (clientHandleSocket < 0) {
            perror("[ERR] accept()");
            exit(1);
        } else {
            char addrBuffer[128];
            printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
            printf("[INF] New connection from %s\n", addrBuffer);
        }

        handleClient(clientHandleSocket);

        close(clientHandleSocket);
    }
}