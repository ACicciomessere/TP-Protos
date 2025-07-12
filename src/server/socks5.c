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
    const int maxRetries = 100; // Necesario para prevenir loops infinitos

    while (totalSent < n && retries < maxRetries) {
        ssize_t nowSent = send(fd, (const char*)buf + totalSent, n - totalSent, flags);
        
        if (nowSent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // El socket se bloquearía, esperamos a que esté listo para escribir
                struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
                int poll_result = poll(&pfd, 1, 5000); // timeout de 5 segs
                
                if (poll_result < 0) {
                    perror("[ERR] poll() in sendFull");
                    return -1;
                } else if (poll_result == 0) {
                    printf("[ERR] send() timeout after 5 seconds\n");
                    return -1;
                } else if (pfd.revents & POLLOUT) {
                    retries++;
                    continue; // Reintentamos
                } else {
                    printf("[ERR] poll() unexpected event: %d\n", pfd.revents);
                    return -1;
                }
            } else {
                perror("[ERR] send()");
                return -1;
            }
        } else if (nowSent == 0) {
            printf("[ERR] send() returned 0, connection may be closed\n");
            return -1;
        } else {
            totalSent += nowSent;
            retries = 0;
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
    
    received = recvFull(clientSocket, receiveBuffer, 2, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive username/password auth header\n");
        return -1;
    }
    
    if (receiveBuffer[0] != 1) {
        printf("[ERR] Invalid username/password auth version: %d\n", receiveBuffer[0]);
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return -1;
    }
    
    int usernameLen = receiveBuffer[1];
    if (usernameLen == 0 || usernameLen > 255) {
        printf("[ERR] Invalid username length: %d\n", usernameLen);
        sendFull(clientSocket, "\x01\x01", 2, 0); 
        return -1;
    }
    
    received = recvFull(clientSocket, receiveBuffer, usernameLen, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive username\n");
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return -1;
    }
    receiveBuffer[usernameLen] = '\0';
    char username[256];
    strncpy(username, receiveBuffer, usernameLen);
    username[usernameLen] = '\0';
    
    received = recvFull(clientSocket, receiveBuffer, 1, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive password length\n");
        sendFull(clientSocket, "\x01\x01", 2, 0);
        return -1;
    }
    
    int passwordLen = receiveBuffer[0];
    if (passwordLen == 0 || passwordLen > 255) {
        printf("[ERR] Invalid password length: %d\n", passwordLen);
        sendFull(clientSocket, "\x01\x01", 2, 0); 
        return -1;
    }
    
    received = recvFull(clientSocket, receiveBuffer, passwordLen, 0);
    if (received < 0) {
        printf("[ERR] Failed to receive password\n");
        sendFull(clientSocket, "\x01\x01", 2, 0);  
        return -1;
    }
    receiveBuffer[passwordLen] = '\0';
    char password[256];
    strncpy(password, receiveBuffer, passwordLen);
    password[passwordLen] = '\0';
    
    printf("[INF] Authentication attempt: username='%s'\n", username);
    
    if (validateUser(username, password, args)) {
        if (authenticated_user) {
            strncpy(authenticated_user, username, MAX_USERNAME_LEN - 1);
            authenticated_user[MAX_USERNAME_LEN - 1] = '\0';
        }
        
        if (sendFull(clientSocket, "\x01\x00", 2, 0) < 0) {
            printf("[ERR] Failed to send auth success response\n");
            return -1;
        }
        return 0;
    } else {
        // Fallo
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
        printf("[ERR] Client specified invalid version: %d\n", receiveBuffer[0]);
        return -1;
    }

    int nmethods = receiveBuffer[1];
    received = recvFull(clientSocket, receiveBuffer, nmethods, 0);
    if (received < 0)
        return -1;

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
    
    // Chequeamos si tenemos usuarios configurados
    if (args) {
        for (int i = 0; i < MAX_USERS; i++) {
            if (args->users[i].name && args->users[i].pass) {
                hasUsersConfigured = 1;
                break;
            }
        }
    }
    
    if (hasUsersConfigured) {
        // Los usuarios estan configurados, requerimos autenticacion por nombre de usuario y contraseña
        if (hasUserPass) {
            printf("[INF] Using username/password authentication (required)\n");
            if (sendFull(clientSocket, "\x05\x02", 2, 0) < 0)
                return -1;
                
            return handleUsernamePasswordAuth(clientSocket, args, authenticated_user);
        } else {
            printf("[ERR] Authentication required but client doesn't support username/password!\n");
            if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
                return -1;

            printf("[INF] Waiting for client to close the connection.\n");
            while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
            return -1;
        }
    } else if (hasNoAuth) {
        // Si no tenemos usuarios configurados, no permitimos auth
        printf("[INF] Using no authentication (no users configured)\n");
        if (sendFull(clientSocket, "\x05\x00", 2, 0) < 0)
            return -1;
        return 0;
    } else {
        printf("[ERR] No acceptable authentication method found!\n");
        if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
            return -1;

        printf("[INF] Waiting for client to close the connection.\n");
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
        // El cliente solicita conectarse a un dir. IPV4
        addrHints.ai_family = AF_INET;

        // Leemos la IP
        struct in_addr addr;
        received = recvFull(clientSocket, &addr, 4, 0);
        if (received < 0)
            return -1;

        // Leemos el nro de puerto
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // Nos guardamos el puerto y a la IP la pasamos a string
        port = ntohs(portBuf);
        inet_ntop(AF_INET, &addr, hostname, INET_ADDRSTRLEN);
    } else if (receiveBuffer[3] == 3) {
        // El cliente pide conectarse a un dominio
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
        // El cliente solicito conectarse a un dir. IPV6
        addrHints.ai_family = AF_INET6;

        // Leemos la IP
        struct in6_addr addr;
        received = recvFull(clientSocket, &addr, 16, 0);
        if (received < 0)
            return -1;

        // Leemos el nro de puerto
        in_port_t portBuf;
        received = recvFull(clientSocket, &portBuf, 2, 0);
        if (received < 0)
            return -1;

        // Nos guardamos el puerto y a la IP la pasamos a string
        port = ntohs(portBuf);
        inet_ntop(AF_INET6, &addr, hostname, INET6_ADDRSTRLEN);
    } else {
        sendFull(clientSocket, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0);
        return -1;
    }

    printf("[INF] Client asked to connect to: %s:%d\n", hostname, port);

    char service[6] = {0};
    sprintf(service, "%d", port);

    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, connectAddresses);
    if (getAddrStatus != 0) {
        printf("[ERR] getaddrinfo() failed: %s\n", gai_strerror(getAddrStatus));

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

    // Contamos las direcciones y imprimimos todas las opciones de addrinfo
    for (struct addrinfo* aip = *connectAddresses; aip != NULL; aip = aip->ai_next) {
        printf("[INF] Option %i: %s (%s %s) %s %s (Flags: ", aipIndex++, printFamily(aip), printType(aip), printProtocol(aip), aip->ai_canonname ? aip->ai_canonname : "-", printAddressPort(aip, addrBuf));
        printFlags(aip);
        printf(")\n");
        total_addresses++;
        if (aip->ai_family == AF_INET) ipv4_count++;
        else if (aip->ai_family == AF_INET6) ipv6_count++;
    }
    
    printf("[INF] Attempting to connect to %d addresses (%d IPv4, %d IPv6)\n", 
           total_addresses, ipv4_count, ipv6_count);

    // Primero intentamos IPv6, luego IPv4
    int sock = -1;
    char addrBuffer[128];
    int attempt = 0;
    int last_errno = 0;
    const char* last_error_type = "unknown";
    
    // Intentamos IPv6
    for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        if (addr->ai_family != AF_INET6) continue;
        
        attempt++;
        printf("[INF] Attempt %d/%d: Trying IPv6 %s\n", attempt, total_addresses, printAddressPort(addr, addrBuffer));
        
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            printf("[INF] Failed to create socket for %s: %s\n", printAddressPort(addr, addrBuffer), strerror(errno));
            last_errno = errno;
            last_error_type = "socket creation";
            continue;
        }
        
        int connect_result = connect_with_timeout(sock, addr->ai_addr, addr->ai_addrlen, CONNECTION_TIMEOUT_MS);
        if (connect_result == 1) {
            printf("[INF] Successfully connected to: %s (%s %s) %s %s (Flags: ", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf));
            printFlags(addr);
            printf(")\n");
            break;  // Exitoso
        } else {
            last_errno = errno;
            if (connect_result == 0) {
                printf("[INF] Connection to %s timed out after %dms\n", printAddressPort(addr, addrBuffer), CONNECTION_TIMEOUT_MS);
                last_error_type = "timeout";
            } else {
                printf("[INF] Connection to %s failed: %s\n", printAddressPort(addr, addrBuffer), strerror(errno));
                last_error_type = "connection failed";
            }
            close(sock);
            sock = -1;
            
            // Esperamos un poco antes de intentar nuevamente
            if (RETRY_DELAY_MS > 0) {
                struct timespec delay = {0, RETRY_DELAY_MS * 1000000};  // Convertimos ms a ns
                nanosleep(&delay, NULL);
            }
        }
    }
    
    // Intentamos IPv4
    if (sock == -1) {
        for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
            if (addr->ai_family != AF_INET) continue;
            
            attempt++;
            printf("[INF] Attempt %d/%d: Trying IPv4 %s\n", attempt, total_addresses, printAddressPort(addr, addrBuffer));
            
            sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (sock < 0) {
                printf("[INF] Failed to create socket for %s: %s\n", printAddressPort(addr, addrBuffer), strerror(errno));
                last_errno = errno;
                last_error_type = "socket creation";
                continue;
            }
            
            int connect_result = connect_with_timeout(sock, addr->ai_addr, addr->ai_addrlen, CONNECTION_TIMEOUT_MS);
            if (connect_result == 1) {
                printf("[INF] Successfully connected to: %s (%s %s) %s %s (Flags: ", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf));
                printFlags(addr);
                printf(")\n");
                break;  // Exitoso
            } else {
                last_errno = errno;
                if (connect_result == 0) {
                    printf("[INF] Connection to %s timed out after %dms\n", printAddressPort(addr, addrBuffer), CONNECTION_TIMEOUT_MS);
                    last_error_type = "timeout";
                } else {
                    printf("[INF] Connection to %s failed: %s\n", printAddressPort(addr, addrBuffer), strerror(errno));
                    last_error_type = "connection failed";
                }
                close(sock);
                sock = -1;
                
                // Esperamos un poco antes de intentar nuevamente
                if (RETRY_DELAY_MS > 0) {
                    struct timespec delay = {0, RETRY_DELAY_MS * 1000000};
                    nanosleep(&delay, NULL);
                }
            }
        }
    }

    freeaddrinfo(*connectAddresses);

    if (sock == -1) {
        printf("[ERR] Failed to connect to any of the %d available addresses. Last error: %s (%s)\n", 
               total_addresses, last_error_type, strerror(last_errno));
        
        // Reporte de errores mejorado basado en el tipo de falla
        char socks_error = '\x05';  // Default: Connection refused
        if (strcmp(last_error_type, "timeout") == 0) {
            socks_error = '\x04';  // Host unreachable (timeout sugiere problema de red)
        } else if (strcmp(last_error_type, "socket creation") == 0) {
            socks_error = '\x01';  // General SOCKS server failure
        }
        
        char errorMessage[10] = "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00";
        errorMessage[1] = socks_error;
        sendFull(clientSocket, errorMessage, 10, 0);
        return -1;
    }

    *remoteSocket = sock;

    // Obtenemos y mostramos la direccion y puerto en el que nuestro socket se enlazo
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    if (getsockname(sock, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Remote socket bound at %s\n", addrBuffer);
    } else
        perror("[WRN] Failed to getsockname() for remote socket");

    // Enviamos una respuesta al cliente: SUCCESS, luego enviamos la direccion a la que nuestro socket se enlazo
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

    // Creamos estructuras de poll para decir que estamos esperando bytes para leer en ambos sockets
    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;

    // Lo que viene por clientSocket, lo enviamos a remoteSocket. Lo que viene por remoteSocket, lo enviamos a clientSocket.
    // Esto se repite hasta que el cliente o el servidor remoto cierren la conexion, en cuyo caso cerramos ambas conexiones.
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
