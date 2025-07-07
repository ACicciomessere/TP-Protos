#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "socks5.h"
#include "util.h"
#include "../shared/shared.h"

#define READ_BUFFER_SIZE 2048
#define MAX_HOSTNAME_LENGTH 255

/**
 * Receives a full buffer of data from a socket, by receiving data until the requested amount
 * of bytes is reached. Returns the amount of bytes received, or -1 if receiving failed before
 * that amount was reached.
 */
static ssize_t recvFull(int fd, void* buf, size_t n, int flags) {
    size_t totalReceived = 0;
    int retries = 0;
    const int maxRetries = 100; // Prevent infinite loops

    while (totalReceived < n && retries < maxRetries) {
        ssize_t nowReceived = recv(fd, (char*)buf + totalReceived, n - totalReceived, flags);
        
        if (nowReceived < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket would block, wait for data to be ready
                struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
                int poll_result = poll(&pfd, 1, 5000); // 5 second timeout
                
                if (poll_result < 0) {
                    perror("[ERR] poll() in recvFull");
                    return -1;
                } else if (poll_result == 0) {
                    printf("[ERR] recv() timeout after 5 seconds\n");
                    return -1;
                } else if (pfd.revents & POLLIN) {
                    retries++;
                    continue; // Try recv again
                } else {
                    printf("[ERR] poll() unexpected event: %d\n", pfd.revents);
                    return -1;
                }
            } else {
                perror("[ERR] recv()");
                return -1;
            }
        } else if (nowReceived == 0) {
            // Connection closed by peer
            if (totalReceived == 0) {
                printf("[ERR] Connection closed by peer before any data received\n");
                return -1;
            } else {
                // Partial data received before close - return what we got
                printf("[WARN] Connection closed by peer, partial data received: %zu/%zu bytes\n", 
                       totalReceived, n);
                return totalReceived;
            }
        } else {
            totalReceived += nowReceived;
            retries = 0; // Reset retry counter on successful read
        }
    }

    if (retries >= maxRetries) {
        printf("[ERR] recvFull() exceeded maximum retries\n");
        return -1;
    }

    return totalReceived;
}

/**
 * Sends a full buffer of data from a socket, by sending data until the requested amount
 * of bytes is reached. Returns the amount of bytes sent, or -1 if sending failed before
 * that amount was reached.
 */
static ssize_t sendFull(int fd, const void* buf, size_t n, int flags) {
    size_t totalSent = 0;
    int retries = 0;
    const int maxRetries = 100; // Prevent infinite loops

    while (totalSent < n && retries < maxRetries) {
        ssize_t nowSent = send(fd, (const char*)buf + totalSent, n - totalSent, flags);
        
        if (nowSent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket would block, wait for socket to be ready for writing
                struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
                int poll_result = poll(&pfd, 1, 5000); // 5 second timeout
                
                if (poll_result < 0) {
                    perror("[ERR] poll() in sendFull");
                    return -1;
                } else if (poll_result == 0) {
                    printf("[ERR] send() timeout after 5 seconds\n");
                    return -1;
                } else if (pfd.revents & POLLOUT) {
                    retries++;
                    continue; // Try send again
                } else {
                    printf("[ERR] poll() unexpected event: %d\n", pfd.revents);
                    return -1;
                }
            } else {
                perror("[ERR] send()");
                return -1;
            }
        } else if (nowSent == 0) {
            // This shouldn't happen with send(), but handle it
            printf("[ERR] send() returned 0, connection may be closed\n");
            return -1;
        } else {
            totalSent += nowSent;
            retries = 0; // Reset retry counter on successful write
        }
    }

    if (retries >= maxRetries) {
        printf("[ERR] sendFull() exceeded maximum retries\n");
        return -1;
    }

    return totalSent;
}

int validateUser(const char* username, const char* password, struct socks5args* args) {
    if (!username || !password || !args) {
        return 0;
    }
    
    // Check against configured users
    for (int i = 0; i < MAX_USERS; i++) {
        if (args->users[i].name && args->users[i].pass) {
            if (strcmp(username, args->users[i].name) == 0 && 
                strcmp(password, args->users[i].pass) == 0) {
                printf("[INF] User '%s' authenticated successfully\n", username);
                return 1;
            }
        }
    }
    
    printf("[ERR] Authentication failed for user '%s'\n", username);
    return 0;
}

int handleUsernamePasswordAuth(int clientSocket, struct socks5args* args, char* authenticated_user) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];
    
    // Read the username/password request: VER, ULEN, UNAME, PLEN, PASSWD
    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive username/password auth header\n");
        return -1;
    }
    
    // Check version (should be 1 for username/password auth)
    if (receiveBuffer[0] != 1) {
        printf("[ERR] Invalid username/password auth version: %d\n", receiveBuffer[0]);
        sendFull(clientSocket, "\x01\x01", 2, 0);  // Status: failure
        return -1;
    }
    
    // Get username length
    int usernameLen = receiveBuffer[1];
    if (usernameLen == 0 || usernameLen > 255) {
        printf("[ERR] Invalid username length: %d\n", usernameLen);
        sendFull(clientSocket, "\x01\x01", 2, 0);  // Status: failure
        return -1;
    }
    
    // Read username
    received = recvFull(clientSocket, receiveBuffer, usernameLen, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive username\n");
        sendFull(clientSocket, "\x01\x01", 2, 0);  // Status: failure
        return -1;
    }
    receiveBuffer[usernameLen] = '\0';
    char username[256];
    strncpy(username, receiveBuffer, usernameLen);
    username[usernameLen] = '\0';
    
    // Read password length
    received = recvFull(clientSocket, receiveBuffer, 1, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive password length\n");
        sendFull(clientSocket, "\x01\x01", 2, 0);  // Status: failure
        return -1;
    }
    
    int passwordLen = receiveBuffer[0];
    if (passwordLen == 0 || passwordLen > 255) {
        printf("[ERR] Invalid password length: %d\n", passwordLen);
        sendFull(clientSocket, "\x01\x01", 2, 0);  // Status: failure
        return -1;
    }
    
    // Read password
    received = recvFull(clientSocket, receiveBuffer, passwordLen, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive password\n");
        sendFull(clientSocket, "\x01\x01", 2, 0);  // Status: failure
        return -1;
    }
    receiveBuffer[passwordLen] = '\0';
    char password[256];
    strncpy(password, receiveBuffer, passwordLen);
    password[passwordLen] = '\0';
    
    printf("[INF] Authentication attempt: username='%s'\n", username);
    
    // Validate user credentials
    if (validateUser(username, password, args)) {
        // Store the authenticated username
        if (authenticated_user) {
            strncpy(authenticated_user, username, MAX_USERNAME_LEN - 1);
            authenticated_user[MAX_USERNAME_LEN - 1] = '\0';
        }
        
        // Send success response
        if (sendFull(clientSocket, "\x01\x00", 2, 0) < 0) {
            printf("[ERR] Failed to send auth success response\n");
            return -1;
        }
        return 0;
    } else {
        // Send failure response
        if (sendFull(clientSocket, "\x01\x01", 2, 0) < 0) {
            printf("[ERR] Failed to send auth failure response\n");
        }
        return -1;
    }
}

int handleClient(int clientSocket, struct socks5args* args) {
    char authenticated_user[MAX_USERNAME_LEN] = {0};
    
    if (handleAuthNegotiation(clientSocket, args, authenticated_user))
        return -1;

    // The client can now start sending requests.

    struct addrinfo* connectAddresses;
    if (handleRequest(clientSocket, &connectAddresses))
        return -1;

    // Now we must conenct to the requested server and reply with success/error code.

    int remoteSocket = -1;
    if (handleConnectAndReply(clientSocket, &connectAddresses, &remoteSocket))
        return -1;

    // The connection has been established! Now the client and requested server can talk to each other.
    // If we have an authenticated user, update their connection stats
    if (authenticated_user[0] != '\0') {
        mgmt_update_user_stats(authenticated_user, 0, 1); // New connection
    }

    int status = handleConnectionData(clientSocket, remoteSocket, authenticated_user);
    
    // Update connection end stats
    if (authenticated_user[0] != '\0') {
        mgmt_update_user_stats(authenticated_user, 0, -1); // Connection ended
    }
    
    close(remoteSocket);
    return status;
}

int handleAuthNegotiation(int clientSocket, struct socks5args* args, char* authenticated_user) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // Socks5 starts with the client sending VER, NMETHODS, followed by that amount of METHODS. Let's read VER and NMETHODS.
    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0)
        return -1;

    // Check that version is 5
    if (receiveBuffer[0] != 5) {
        printf("[ERR] Client specified invalid version: %d\n", receiveBuffer[0]);
        return -1;
    }

    // Read NMETHODS methods.
    int nmethods = receiveBuffer[1];
    received = recvFull(clientSocket, receiveBuffer, nmethods, 0);
    if (received < 0)
        return -1;

    // Check what authentication methods the client supports
    int hasNoAuth = 0;
    int hasUserPass = 0;
    int hasUsersConfigured = 0;
    
    printf("[INF] Client specified auth methods: ");
    for (int i = 0; i < nmethods; i++) {
        if (receiveBuffer[i] == SOCKS5_AUTH_NONE) {
            hasNoAuth = 1;
        } else if (receiveBuffer[i] == SOCKS5_AUTH_USERPASS) {
            hasUserPass = 1;
        }
        printf("%02x%s", receiveBuffer[i], i + 1 == nmethods ? "\n" : ", ");
    }
    
    // Check if we have any users configured
    if (args) {
        for (int i = 0; i < MAX_USERS; i++) {
            if (args->users[i].name && args->users[i].pass) {
                hasUsersConfigured = 1;
                break;
            }
        }
    }
    
    // Determine which authentication method to use
    if (hasUsersConfigured) {
        // Users are configured, require username/password authentication
        if (hasUserPass) {
            printf("[INF] Using username/password authentication (required)\n");
            if (sendFull(clientSocket, "\x05\x02", 2, 0) < 0)
                return -1;
                
            // Perform username/password authentication
            return handleUsernamePasswordAuth(clientSocket, args, authenticated_user);
        } else {
            // Users are configured but client doesn't support username/password auth
            printf("[ERR] Authentication required but client doesn't support username/password!\n");
            if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
                return -1;

            // Wait for the client to close the TCP connection.
            printf("[INF] Waiting for client to close the connection.\n");
            while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
            return -1;
        }
    } else if (hasNoAuth) {
        // No users configured, allow no authentication
        printf("[INF] Using no authentication (no users configured)\n");
        if (sendFull(clientSocket, "\x05\x00", 2, 0) < 0)
            return -1;
        return 0;
    } else {
        // No acceptable authentication method found
        printf("[ERR] No acceptable authentication method found!\n");
        if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
            return -1;

        // Wait for the client to close the TCP connection.
        printf("[INF] Waiting for client to close the connection.\n");
        while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
        return -1;
    }
}

int handleRequest(int clientSocket, struct addrinfo** connectAddresses) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    // Read from a client request: VER, CMD, RSV, ATYP.
    received = recvFull(clientSocket, receiveBuffer, 4, 0);
    if (received < 0)
        return -1;

    // Check that the CMD the client specified is X'01' "connect". Otherwise, send and error and close the TCP connection.
    if (receiveBuffer[1] != 1) {
        // The reply specified REP as X'07' "Command not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    // We will store the hostname and port in these variables. If the client asked to connect to an IP, we
    // will print it into hostname and then pass it throught getaddrinfo().
    // Is this the best option? Definitely not, but it's kinda easier ;)
    char hostname[MAX_HOSTNAME_LENGTH + 1];
    int port = 0;

    // The hints for getaddrinfo. We will specify we want a stream TCP socket.
    struct addrinfo addrHints;
    memset(&addrHints, 0, sizeof(addrHints));
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;

    // Check ATYP and print the address/hostname the client asked to connect to.
    if (receiveBuffer[3] == 1) {
        // Client requested to connect to an IPv4 address.
        addrHints.ai_family = AF_INET;

        // Read the IPv4 address (4 bytes).
        struct in_addr addr;
        received = recvFull(clientSocket, &addr, 4, 0);
        if (received < 0)
            return -1;

        // Read the port number (2 bytes).
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // Store the port and convert the IP to a hostname string.
        port = ntohs(portBuf);
        inet_ntop(AF_INET, &addr, hostname, INET_ADDRSTRLEN);
    } else if (receiveBuffer[3] == 3) {
        // Client requested to connect to a domain name.
        // Read one byte, the length of the domain name string.
        received = recvFull(clientSocket, receiveBuffer, 1, 0);
        if (received < 0)
            return -1;

        // Read the domain name string into the 'hostname' buffer.
        int hostnameLength = receiveBuffer[0];
        received = recvFull(clientSocket, hostname, hostnameLength, 0);
        if (received < 0)
            return -1;

        // Read the port number.
        in_port_t portBuffer;
        received = recvFull(clientSocket, &portBuffer, 2, 0);
        if (received < 0)
            return -1;

        // Store the port number and hostname.
        port = ntohs(portBuffer);
        hostname[hostnameLength] = '\0';
    } else if (receiveBuffer[3] == 4) {
        // Client requested to connect to an IPv6 address.
        addrHints.ai_family = AF_INET6;

        // Read the IPv6 address (16 bytes).
        struct in6_addr addr;
        received = recvFull(clientSocket, &addr, 16, 0);
        if (received < 0)
            return -1;

        // Read the port number (2 bytes).
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // Store the port and convert the IP to a hostname string.
        port = ntohs(portBuf);
        inet_ntop(AF_INET6, &addr, hostname, INET6_ADDRSTRLEN);
    } else {
        // The reply specified REP as X'08' "Address type not supported", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    printf("[INF] Client asked to connect to: %s:%d\n", hostname, port);

    // For "service", we will indicate the port number
    char service[6] = {0};
    sprintf(service, "%d", port);

    // Call getaddrinfo to get the prepared addrinfo structures to connect to.
    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, connectAddresses);
    if (getAddrStatus != 0) {
        printf("[ERR] getaddrinfo() failed: %s\n", gai_strerror(getAddrStatus));

        // The reply specifies ATYP as IPv4 and BND as 0.0.0.0:0.
        char errorMessage[10] = "\x05 \x00\x01\x00\x00\x00\x00\x00\x00";
        // We calculate the REP value based on the type of error returned by getaddrinfo
        errorMessage[1] =
            getAddrStatus == EAI_FAMILY   ? '\x08'  // REP is "Address type not supported"
            : getAddrStatus == EAI_NONAME ? '\x04'  // REP is "Host Unreachable"
                                          : '\x01'; // REP is "General SOCKS server failure"
        sendFull(clientSocket, errorMessage, 10, 0);
        return -1;
    }

    return 0;
}

int handleConnectAndReply(int clientSocket, struct addrinfo** connectAddresses, int* remoteSocket) {
    char addrBuf[64];
    int aipIndex = 0;

    // Print all the addrinfo options, just for debugging.
    for (struct addrinfo* aip = *connectAddresses; aip != NULL; aip = aip->ai_next) {
        printf("[INF] Option %i: %s (%s %s) %s %s (Flags: ", aipIndex++, printFamily(aip), printType(aip), printProtocol(aip), aip->ai_canonname ? aip->ai_canonname : "-", printAddressPort(aip, addrBuf));
        printFlags(aip);
        printf(")\n");
    }

    // Find the first addrinfo option in which we can both open a socket, and connect to the remote server.
    int sock = -1;
    char addrBuffer[128];
    for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            printf("[INF] Failed to create remote socket on %s\n", printAddressPort(addr, addrBuffer));
        } else {
            errno = 0;
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                printf("[INF] Failed to connect() remote socket to %s: %s\n", printAddressPort(addr, addrBuffer), strerror(errno));
                close(sock);
                sock = -1;
            } else {
                printf("[INF] Successfully connected to: %s (%s %s) %s %s (Flags: ", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf));
                printFlags(addr);
                printf(")\n");
            }
        }
    }

    freeaddrinfo(*connectAddresses);

    if (sock == -1) {
        printf("[ERR] Failed to connect to any of the available options.\n");
        // The reply specified REP as X'05' "Connection refused", ATYP as IPv4 and BND as 0.0.0.0:0.
        sendFull(clientSocket, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    *remoteSocket = sock;

    // Get and print the address and port at which our socket got bound.
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Remote socket bound at %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname() for remote socket");

    // Send a server reply: SUCCESS, then send the address to which our socket is bound.
    if (sendFull(clientSocket, "\x05\x00\x00", 3, 0) < 0)
        return -1;

    switch (boundAddress.ss_family) {
        case AF_INET:
            // Send: '\x01' (ATYP identifier for IPv4) followed by the IP and PORT.
            if (sendFull(clientSocket, "\x01", 1, 0) < 0)
                return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in*)&boundAddress)->sin_addr, 4, 0) < 0)
                return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in*)&boundAddress)->sin_port, 2, 0) < 0)
                return -1;
            break;

        case AF_INET6:
            // Send: '\x04' (ATYP identifier for IPv6) followed by the IP and PORT.
            if (sendFull(clientSocket, "\x04", 1, 0) < 0)
                return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in6*)&boundAddress)->sin6_addr, 16, 0) < 0)
                return -1;
            if (sendFull(clientSocket, &((struct sockaddr_in6*)&boundAddress)->sin6_port, 2, 0) < 0)
                return -1;
            break;

        default:
            // We don't know the address type? Send IPv4 0.0.0.0:0.
            if (sendFull(clientSocket, "\x01\x00\x00\x00\x00\x00\x00", 7, 0) < 0)
                return -1;
            break;
    }

    return 0;
}

int handleConnectionData(int clientSocket, int remoteSocket, const char* authenticated_user) {
    ssize_t received;
    char receiveBuffer[4096];

    // Create poll structures to say we are waiting for bytes to read on both sockets.
    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;

    // What comes in through clientSocket, we send to remoteSocket. What comes in through remoteSocket, we send to clientSocket.
    // This gets repeated until either the client or remote server closes the connection, at which point we close both connections.
    int alive = 1;
    do {
        int pollResult = poll(pollFds, 2, -1);
        if (pollResult < 0) {
            printf("[ERR] Poll returned %d: ", pollResult);
            perror(NULL);
            return -1;
        }

        for (int i = 0; i < 2 && alive; i++) {
            if (pollFds[i].revents == 0)
                continue;

            received = recv(pollFds[i].fd, receiveBuffer, sizeof(receiveBuffer), 0);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No data available right now, continue with next socket
                    continue;
                } else {
                    perror("[ERR] recv() in data relay");
                    alive = 0;
                }
            } else if (received == 0) {
                // Connection closed by peer
                printf("[INF] Connection closed by peer\n");
                alive = 0;
            } else {
                int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;
                ssize_t sent = sendFull(otherSocket, receiveBuffer, received, 0);
                if (sent != received) {
                    printf("[ERR] Failed to send all data: sent %zd/%zd bytes\n", sent, received);
                    alive = 0;
                } else {
                    // Actualizar estadísticas con los bytes transferidos
                    if (authenticated_user && authenticated_user[0] != '\0') {
                        mgmt_update_user_stats(authenticated_user, sent, 0);
                    } else {
                        mgmt_update_stats(sent, 0);
                    }
                }
            }
        }
    } while (alive);

    return 0;
}