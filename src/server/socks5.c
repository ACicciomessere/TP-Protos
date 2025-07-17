#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "socks5.h"
#include "util.h"
#include "../shared/shared.h"
#include "../logger.h"

#define READ_BUFFER_SIZE 2048
#define MAX_HOSTNAME_LENGTH 255
#define CONNECTION_TIMEOUT_MS 10000  // 10 seconds timeout per connection attempt
#define RETRY_DELAY_MS 100          // 100ms delay between attempts


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
                    log_error("poll() in recvFull failed: %s", strerror(errno));
                    return -1;
                } else if (poll_result == 0) {
                    log_error("recv() timeout after 5 seconds");
                    return -1;
                } else if (pfd.revents & POLLIN) {
                    retries++;
                    continue; // Try recv again
                } else {
                    log_error("poll() unexpected event: %d", pfd.revents);
                    return -1;
                }
            } else {
                log_error("recv() failed: %s", strerror(errno));
                return -1;
            }
        } else if (nowReceived == 0) {
            // Connection closed by peer
            if (totalReceived == 0) {
                log_error("Connection closed by peer before any data received");
                return -1;
            } else {
                // Partial data received before close - return what we got
                log_warn("Connection closed by peer, partial data received: %zu/%zu bytes", 
                       totalReceived, n);
                return totalReceived;
            }
        } else {
            totalReceived += nowReceived;
            retries = 0; // Reset retry counter on successful read
        }
    }

    if (retries >= maxRetries) {
        log_error("recvFull() exceeded maximum retries");
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
    const int maxRetries = 100; // Necesario para prevenir loops infinitos

    while (totalSent < n && retries < maxRetries) {
        ssize_t nowSent = send(fd, (const char*)buf + totalSent, n - totalSent, flags);
        
        if (nowSent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // El socket se bloquearía, esperamos a que esté listo para escribir
                struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
                int poll_result = poll(&pfd, 1, 5000); // timeout de 5 segs
                
                if (poll_result < 0) {
                    log_error("poll() in sendFull failed: %s", strerror(errno));
                    return -1;
                } else if (poll_result == 0) {
                    log_error("send() timeout after 5 seconds");
                    return -1;
                } else if (pfd.revents & POLLOUT) {
                    retries++;
                    continue; // Reintentamos
                } else {
                    log_error("poll() unexpected event: %d", pfd.revents);
                    return -1;
                }
            } else {
                log_error("send() failed: %s", strerror(errno));
                return -1;
            }
        } else if (nowSent == 0) {
            log_error("send() returned 0, connection may be closed");
            return -1;
        } else {
            totalSent += nowSent;
            retries = 0;
        }
    }

    if (retries >= maxRetries) {
        log_error("sendFull() exceeded maximum retries");
        return -1;
    }

    return totalSent;
}

int validateUser(const char* username, const char* password, struct socks5args* args) {
    if (!username || !password || !args) {
        return 0;
    }
    
    for (int i = 0; i < MAX_USERS; i++) {
        if (args->users[i].name && args->users[i].pass) {
            if (strcmp(username, args->users[i].name) == 0 && 
                strcmp(password, args->users[i].pass) == 0) {
                log_info("User '%s' authenticated successfully", username);
                log_access(username, "AUTH_OK", "User authenticated successfully");
                return 1;
            }
        }
    }
    
    log_warn("Authentication failed for user '%s'", username);
    log_access(username, "AUTH_FAIL", "Invalid credentials provided");
    return 0;
}

int handleUsernamePasswordAuth(int clientSocket, struct socks5args* args, char* authenticated_user) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];
    
    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0) {
        log_error("Failed to receive username/password auth header");
        return -1;
    }
    
    if (receiveBuffer[0] != 1) {
        log_error("Invalid username/password auth version: %d", receiveBuffer[0]);
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return -1;
    }
    
    int usernameLen = receiveBuffer[1];
    if (usernameLen == 0 || usernameLen > 255) {
        log_error("Invalid username length: %d", usernameLen);
        sendFull(clientSocket, "\x01\x01", 2, 0); 
        return -1;
    }
    
    received = recvFull(clientSocket, receiveBuffer, usernameLen, 0);
    if (received < 0) {
        log_error("Failed to receive username");
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return -1;
    }
    receiveBuffer[usernameLen] = '\0';
    char username[256];
    strncpy(username, receiveBuffer, usernameLen);
    username[usernameLen] = '\0';
    
    received = recvFull(clientSocket, receiveBuffer, 1, 0);
    if (received < 0) {
        log_error("Failed to receive password length");
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return -1;
    }
    
    int passwordLen = receiveBuffer[0];
    if (passwordLen == 0 || passwordLen > 255) {
        log_error("Invalid password length: %d", passwordLen);
        sendFull(clientSocket, "\x01\x01", 2, 0); 
        return -1;
    }
    
    received = recvFull(clientSocket, receiveBuffer, passwordLen, 0);
    if (received < 0) {
        log_error("Failed to receive password");
        sendFull(clientSocket, "\x01\x01", 2, 0);  
        return -1;
    }
    receiveBuffer[passwordLen] = '\0';
    char password[256];
    strncpy(password, receiveBuffer, passwordLen);
    password[passwordLen] = '\0';
    
    log_info("Authentication attempt: username='%s'", username);
    
    if (validateUser(username, password, args)) {
        if (authenticated_user) {
            strncpy(authenticated_user, username, MAX_USERNAME_LEN - 1);
            authenticated_user[MAX_USERNAME_LEN - 1] = '\0';
        }
        
        if (sendFull(clientSocket, "\x01\x00", 2, 0) < 0) {
            log_error("Failed to send auth success response");
            return -1;
        }
        return 0;
    } else {
        // Fallo
        if (sendFull(clientSocket, "\x01\x01", 2, 0) < 0) {
            log_error("Failed to send auth failure response");
        }
        return -1;
    }
}

int handleClient(int clientSocket, struct socks5args* args) {
    char authenticated_user[MAX_USERNAME_LEN] = {0};
    
    if (handleAuthNegotiation(clientSocket, args, authenticated_user))
        return -1;

    // Ahora el cliente puede empezar a enviar solicitudes

    struct addrinfo* connectAddresses;
    if (handleRequest(clientSocket, &connectAddresses))
        return -1;

     // Ahora nos podemos conectar al servidor solicitado

    int remoteSocket = -1;
    if (handleConnectAndReply(clientSocket, &connectAddresses, &remoteSocket))
        return -1;

        // Se establece la conexion, a partir de aca el cliente y el server pueden comunicarse
        // Si tenemos un usuario autenticado, ademas tenemos q actualizar sus estadisticas de conexion
    if (authenticated_user[0] != '\0') {
        mgmt_update_user_stats(authenticated_user, 0, 1); 
    }

    int status = handleConnectionData(clientSocket, remoteSocket, authenticated_user);
    
    if (authenticated_user[0] != '\0') {
        mgmt_update_user_stats(authenticated_user, 0, -1); 
    }
    
    close(remoteSocket);
    return status;
}

int handleAuthNegotiation(int clientSocket, struct socks5args* args, char* authenticated_user) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0)
        return -1;

    if (receiveBuffer[0] != 5) {
        log_error("Client specified invalid version: %d", receiveBuffer[0]);
        return -1;
    }

    int nmethods = receiveBuffer[1];
    received = recvFull(clientSocket, receiveBuffer, nmethods, 0);
    if (received < 0)
        return -1;

    int hasNoAuth = 0;
    int hasUserPass = 0;
    int hasUsersConfigured = 0;
    
    log_debug("Client specified %d auth methods", nmethods);
    for (int i = 0; i < nmethods; i++) {
        if (receiveBuffer[i] == SOCKS5_AUTH_NONE) {
            hasNoAuth = 1;
        } else if (receiveBuffer[i] == SOCKS5_AUTH_USERPASS) {
            hasUserPass = 1;
        }
        log_debug("Auth method supported by client: 0x%02x", receiveBuffer[i]);
    }
    
    // Check if we have configured users
    if (args) {
        for (int i = 0; i < MAX_USERS; i++) {
            if (args->users[i].name && args->users[i].pass) {
                hasUsersConfigured = 1;
                break;
            }
        }
    }
    
    if (hasUsersConfigured) {
        // Users are configured, we require username/password authentication
        if (hasUserPass) {
            log_info("Using username/password authentication (required)");
            if (sendFull(clientSocket, "\x05\x02", 2, 0) < 0)
                return -1;
                
            return handleUsernamePasswordAuth(clientSocket, args, authenticated_user);
        } else {
            log_error("Authentication required but client doesn't support username/password!");
            log_access(NULL, "AUTH_FAIL", "Client does not support required auth method");
            if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
                return -1;

            log_info("Waiting for client to close the connection.");
            while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
            return -1;
        }
    } else if (hasNoAuth) {
        // If we don't have configured users, we don't allow auth
        log_info("Using no authentication (no users configured)");
        log_access(NULL, "AUTH_OK", "No authentication required");
        if (sendFull(clientSocket, "\x05\x00", 2, 0) < 0)
            return -1;
        return 0;
    } else {
        log_error("No acceptable authentication method found!");
        log_access(NULL, "AUTH_FAIL", "No acceptable auth method found");
        if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
            return -1;

        log_info("Waiting for client to close the connection.");
        while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
        return -1;
    }
}

int handleRequest(int clientSocket, struct addrinfo** connectAddresses) {
    ssize_t received;
    char receiveBuffer[READ_BUFFER_SIZE + 1];

    received = recvFull(clientSocket, receiveBuffer, 4, 0);
    if (received < 0)
        return -1;

    if (receiveBuffer[1] != 1) {
        sendFull(clientSocket, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    char hostname[MAX_HOSTNAME_LENGTH + 1];
    int port = 0;

    struct addrinfo addrHints;
    memset(&addrHints, 0, sizeof(addrHints));
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;

    if (receiveBuffer[3] == 1) {
        // The client requests to connect to an IPv4 address
        addrHints.ai_family = AF_INET;

        // Read the IP
        struct in_addr addr;
        received = recvFull(clientSocket, &addr, 4, 0);
        if (received < 0)
            return -1;

        // Read the port number
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // We save the port and convert the IP to a string
        port = ntohs(portBuf);
        inet_ntop(AF_INET, &addr, hostname, INET_ADDRSTRLEN);
    } else if (receiveBuffer[3] == 3) {
        // The client asks to connect to a domain
        received = recvFull(clientSocket, receiveBuffer, 1, 0);
        if (received < 0)
            return -1;

        int hostnameLength = receiveBuffer[0];
        received = recvFull(clientSocket, hostname, hostnameLength, 0);
        if (received < 0)
            return -1;

        in_port_t portBuffer;
        received = recvFull(clientSocket, &portBuffer, 2, 0);
        if (received < 0)
            return -1;

        port = ntohs(portBuffer);
        hostname[hostnameLength] = '\0';
    } else if (receiveBuffer[3] == 4) {
        // The client requested to connect to an IPv6 address
        addrHints.ai_family = AF_INET6;

        // Read the IP
        struct in6_addr addr;
        received = recvFull(clientSocket, &addr, 16, 0);
        if (received < 0)
            return -1;

        // Read the port number
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // We save the port and convert the IP to a string
        port = ntohs(portBuf);
        inet_ntop(AF_INET6, &addr, hostname, INET6_ADDRSTRLEN);
    } else {
        log_error("Unsupported address type: %d", receiveBuffer[3]);
        sendFull(clientSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    log_info("Client asked to connect to: %s:%d", hostname, port);

    char service[6] = {0};
    sprintf(service, "%d", port);

    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, connectAddresses);
    if (getAddrStatus != 0) {
        log_error("getaddrinfo() failed for %s:%s : %s", hostname, service, gai_strerror(getAddrStatus));

        char errorMessage[10] = "\x05 \x00\x01\x00\x00\x00\x00\x00\x00";
        errorMessage[1] =
            getAddrStatus == EAI_FAMILY   ? '\x08'  
            : getAddrStatus == EAI_NONAME ? '\x04' 
                                          : '\x01'; 
        sendFull(clientSocket, errorMessage, 10, 0);
        return -1;
    }

    return 0;
}

static int set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static int set_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
}


int send_socks5_reply(int client_fd, enum socks5_reply code) {
    uint8_t response[10];

    response[0] = SOCKS_VERSION;   // VER
    response[1] = code;            // REP
    response[2] = 0x00;            // RSV
    response[3] = 0x01;            // ATYP = IPv4 (dummy)
    response[4] = 0x00;            // BND.ADDR = 0.0.0.0
    response[5] = 0x00;
    response[6] = 0x00;
    response[7] = 0x00;
    response[8] = 0x00;            // BND.PORT = 0
    response[9] = 0x00;

    ssize_t n = write(client_fd, response, sizeof(response));
    return n == sizeof(response) ? 0 : -1;
}


 // Intenta conectarse a una direccion especifica con timeout
 // Retorna 1 si la conexion es exitosa, 0 si hay timeout o falla, -1 si hay error
static int connect_with_timeout(int sock, const struct sockaddr* addr, socklen_t addrlen, int timeout_ms) {
    // Setea socket a non-blocking
    if (set_nonblocking(sock) < 0) {
        return -1;
    }
    
    // Intenta conectar
    int result = connect(sock, addr, addrlen);
    if (result == 0) {
        // Conexion exitosa
        set_blocking(sock); 
        return 1;
    }
    
    if (errno != EINPROGRESS) {
        // Fallo la conexion
        return 0;
    }
    
    // La conexion esta en progreso, esperamos a que termine
    struct pollfd pfd = {
        .fd = sock,
        .events = POLLOUT,
        .revents = 0
    };
    
    int poll_result = poll(&pfd, 1, timeout_ms);
    if (poll_result < 0) {
        return -1;  // error
    } else if (poll_result == 0) {
        return 0;   // timeout
    }
    
    // Chequeamos si la conexion fue exitosa
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0) {
        return -1;
    }
    
    if (error == 0) {
        // Conexion exitosa
        set_blocking(sock); 
        return 1;
    } else {
        // Fallo la conexion
        errno = error;
        return 0;
    }
}

int handleConnectAndReply(int clientSocket, struct addrinfo** connectAddresses, int* remoteSocket) {
    char addrBuf[64];
    int aipIndex = 0;
    int total_addresses = 0;
    int ipv4_count = 0, ipv6_count = 0;

    // Count the addresses and print all addrinfo options
    for (struct addrinfo* aip = *connectAddresses; aip != NULL; aip = aip->ai_next) {
        printAddressPort(aip, addrBuf);
        log_debug("Resolution option %d: %s (%s)", aipIndex++, addrBuf, printFamily(aip));
        total_addresses++;
        if (aip->ai_family == AF_INET) ipv4_count++;
        else if (aip->ai_family == AF_INET6) ipv6_count++;
    }
    
    log_info("Attempting to connect to %d addresses (%d IPv4, %d IPv6)", 
           total_addresses, ipv4_count, ipv6_count);

    // First we try IPv6, then IPv4
    int sock = -1;
    char addrBuffer[128];
    int attempt = 0;
    int last_errno = 0;
    const char* last_error_type = "unknown";
    
    // Try IPv6
    for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        if (addr->ai_family != AF_INET6) continue;
        
        attempt++;
        printAddressPort(addr, addrBuffer);
        log_info("Attempt %d/%d: Trying IPv6 %s", attempt, total_addresses, addrBuffer);
        
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            log_warn("Failed to create socket for %s: %s", addrBuffer, strerror(errno));
            last_errno = errno;
            last_error_type = "socket creation";
            continue;
        }
        
        int connect_result = connect_with_timeout(sock, addr->ai_addr, addr->ai_addrlen, CONNECTION_TIMEOUT_MS);
        if (connect_result == 1) {
            printAddressPort(addr, addrBuf);
            log_info("Successfully connected to: %s", addrBuf);
            break;  // Success
        } else {
            last_errno = errno;
            if (connect_result == 0) {
                log_warn("Connection to %s timed out after %dms", addrBuffer, CONNECTION_TIMEOUT_MS);
                last_error_type = "timeout";
            } else {
                log_warn("Connection to %s failed: %s", addrBuffer, strerror(errno));
                last_error_type = "connection failed";
            }
            close(sock);
            sock = -1;
            
            // Wait a bit before trying again
            if (RETRY_DELAY_MS > 0) {
                struct timespec delay = {0, RETRY_DELAY_MS * 1000000};  // Convert ms to ns
                nanosleep(&delay, NULL);
            }
        }
    }
    
    // Try IPv4
    if (sock == -1) {
        for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
            if (addr->ai_family != AF_INET) continue;
            
            attempt++;
            printAddressPort(addr, addrBuffer);
            log_info("Attempt %d/%d: Trying IPv4 %s", attempt, total_addresses, addrBuffer);
            
            sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (sock < 0) {
                log_warn("Failed to create socket for %s: %s", addrBuffer, strerror(errno));
                last_errno = errno;
                last_error_type = "socket creation";
                continue;
            }
            
            int connect_result = connect_with_timeout(sock, addr->ai_addr, addr->ai_addrlen, CONNECTION_TIMEOUT_MS);
            if (connect_result == 1) {
                printAddressPort(addr, addrBuf);
                log_info("Successfully connected to: %s", addrBuf);
                break;  // Success
            } else {
                last_errno = errno;
                if (connect_result == 0) {
                    log_warn("Connection to %s timed out after %dms", addrBuffer, CONNECTION_TIMEOUT_MS);
                    last_error_type = "timeout";
                } else {
                    log_warn("Connection to %s failed: %s", addrBuffer, strerror(errno));
                    last_error_type = "connection failed";
                }
                close(sock);
                sock = -1;
                
                // Wait a bit before trying again
                if (RETRY_DELAY_MS > 0) {
                    struct timespec delay = {0, RETRY_DELAY_MS * 1000000};
                    nanosleep(&delay, NULL);
                }
            }
        }
    }

    freeaddrinfo(*connectAddresses);

    if (sock == -1) {
        log_error("Failed to connect to any of the %d available addresses. Last error: %s (%s)", 
               total_addresses, last_error_type, strerror(last_errno));
        
        // Improved error reporting based on the type of failure
        char socks_error = '\x05';  // Default: Connection refused
        if (strcmp(last_error_type, "timeout") == 0) {
            socks_error = '\x04';  // Host unreachable (timeout suggests network issue)
        } else if (strcmp(last_error_type, "socket creation") == 0) {
            socks_error = '\x01';  // General SOCKS server failure
        }
        
        char errorMessage[10] = "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00";
        errorMessage[1] = socks_error;
        sendFull(clientSocket, errorMessage, 10, 0);
        return -1;
    }

    *remoteSocket = sock;

    // Get and display the address and port our socket is bound to
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log_info("Remote socket bound at %s", addrBuffer);
    } else
        log_warn("Failed to getsockname() for remote socket: %s", strerror(errno));

    // Send a response to the client: SUCCESS, then send the address our socket is bound to
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

    // Create poll structures to wait for bytes to read on both sockets
    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;

    // What comes through clientSocket, we send to remoteSocket. What comes through remoteSocket, we send to clientSocket.
    // This is repeated until the client or the remote server closes the connection, in which case we close both connections.
    int alive = 1;
    do {
        int pollResult = poll(pollFds, 2, -1);
        if (pollResult < 0) {
            log_error("Poll returned %d: %s", pollResult, strerror(errno));
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
                    log_error("recv() in data relay: %s", strerror(errno));
                    alive = 0;
                }
            } else if (received == 0) {
                // Connection closed by peer
                log_info("Connection closed by peer");
                alive = 0;
            } else {
                int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;
                ssize_t sent = sendFull(otherSocket, receiveBuffer, received, 0);
                if (sent != received) {
                    log_error("Failed to send all data: sent %zd/%zd bytes", sent, received);
                    alive = 0;
                } else {
                    // Update statistics with the transferred bytes
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
