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
#include "../../utils/util.h"
#include "../../shared.h"
#include "../../utils/logger.h"
#include "../pop3/pop3_sniffer.h"

static void sockaddr_to_string(char *buffer, const struct sockaddr *addr) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &sin->sin_addr, buffer, INET6_ADDRSTRLEN);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, buffer, INET6_ADDRSTRLEN);
    } else {
        strcpy(buffer, "Unknown address family");
    }
}

#define BUFFER_SIZE 1024
#define READ_BUFFER_SIZE 2048
#define MAX_HOSTNAME_LENGTH 255
#define CONNECTION_TIMEOUT_MS 10000  // 10 seconds timeout per connection attempt
#define RETRY_DELAY_MS 100          // 100ms delay between attempts

#define STATE_AUTH 1
#define STATE_REQUEST 2
#define STATE_DONE 3  // o el que necesites como estado final

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
                    log_error("poll() in recvFull: %s", strerror(errno));
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
                log_error("recv(): %s", strerror(errno));
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
                    log_error("poll() in sendFull: %s", strerror(errno));
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
                log_error("send(): %s", strerror(errno));
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
    if (!username || !password) {
        return 0;
    }

    // 1) Verificamos usuarios desde el archivo auth.db
    FILE* file = fopen("auth.db", "r");
    if (file != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), file)) {
            char* db_user = strtok(line, ":");
            char* db_pass = strtok(NULL, "\n");
            if (db_user && db_pass) {
                if (strcmp(username, db_user) == 0 && strcmp(password, db_pass) == 0) {
                    fclose(file);
                    log_access(username, "AUTH_SUCCESS", "User authenticated successfully");
                    return 1;
                }
            }
        }
        fclose(file);
    }

    // 2) Verificamos usuarios cargados dinámicamente en memoria compartida
    shared_data_t* sh = mgmt_get_shared_data();
    if (sh) {
        pthread_mutex_lock(&sh->users_mutex);
        for (int i = 0; i < sh->user_count; i++) {
            if (sh->users[i].active &&
                strcmp(username, sh->users[i].username) == 0 &&
                strcmp(password, sh->users[i].password) == 0) {
                pthread_mutex_unlock(&sh->users_mutex);
                log_access(username, "AUTH_SUCCESS", "User authenticated successfully (shared)");
                return 1;
            }
        }
        pthread_mutex_unlock(&sh->users_mutex);
    }

    // 3) Verificamos usuarios provistos por línea de comandos (args)
    if (args) {
        for (int i = 0; i < MAX_USERS; i++) {
            if (args->users[i].name && args->users[i].pass &&
                args->users[i].name[0] != '\0' && args->users[i].pass[0] != '\0') {
                if (strcmp(username, args->users[i].name) == 0 &&
                    strcmp(password, args->users[i].pass) == 0) {
                    log_access(username, "AUTH_SUCCESS", "User authenticated successfully (args)");
                    return 1;
                }
            }
        }
    }

    log_access(username, "AUTH_FAIL", "Authentication failed for user");
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
    
    // Reset POP3 sniffer state for new connection
    pop3_sniffer_reset();
    
    if (handleAuthNegotiation(clientSocket, args, authenticated_user))
        return -1;

    // Ahora el cliente puede empezar a enviar solicitudes

    struct addrinfo* connectAddresses;
    int dest_port = 0;
    if (handleRequest(clientSocket, &connectAddresses, &dest_port, authenticated_user))
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

    int status = handleConnectionData(clientSocket, remoteSocket, authenticated_user, dest_port, args);
    
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
    
    log_info("Client specified auth methods: ");
    for (int i = 0; i < nmethods; i++) {
        if (receiveBuffer[i] == SOCKS5_AUTH_NONE) {
            hasNoAuth = 1;
        } else if (receiveBuffer[i] == SOCKS5_AUTH_USERPASS) {
            hasUserPass = 1;
        }
        log_info("%02x%s", receiveBuffer[i], i + 1 == nmethods ? "\n" : ", ");
    }
    
    // Chequeamos si tenemos usuarios configurados en args
    if (args) {
        for (int i = 0; i < MAX_USERS && !hasUsersConfigured; i++) {
            if (args->users[i].name && args->users[i].pass &&
                args->users[i].name[0] != '\0' && args->users[i].pass[0] != '\0') {
                hasUsersConfigured = 1;
            }
        }
    }
    // Si no encontramos, chequeamos memoria compartida
    if (!hasUsersConfigured) {
        shared_data_t* sh = mgmt_get_shared_data();
        if (sh) {
            pthread_mutex_lock(&sh->users_mutex);
            for (int i = 0; i < sh->user_count; i++) {
                if (sh->users[i].active) { hasUsersConfigured = 1; break; }
            }
            pthread_mutex_unlock(&sh->users_mutex);
        }
    }
    
    if (hasUsersConfigured) {
        // Los usuarios estan configurados, requerimos autenticacion por nombre de usuario y contraseña
        if (hasUserPass) {
            log_info("Using username/password authentication (required)");
            if (sendFull(clientSocket, "\x05\x02", 2, 0) < 0)
                return -1;
                
            return handleUsernamePasswordAuth(clientSocket, args, authenticated_user);
        } else {
            char client_ip[INET6_ADDRSTRLEN];
            struct sockaddr_storage addr;
            socklen_t addr_len = sizeof(addr);
            getpeername(clientSocket, (struct sockaddr*)&addr, &addr_len);
            sockaddr_to_string(client_ip, (struct sockaddr*)&addr);
            log_error("Auth required, but client at %s does not support username/password.", client_ip);
            if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
                return -1;

            log_info("Waiting for client to close the connection.");
            while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
            return -1;
        }
    } else if (hasNoAuth) {
        // Si no tenemos usuarios configurados, no permitimos auth
        log_info("Using no authentication (no users configured)");
        if (sendFull(clientSocket, "\x05\x00", 2, 0) < 0)
            return -1;
        return 0;
    } else {
        char client_ip[INET6_ADDRSTRLEN];
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        getpeername(clientSocket, (struct sockaddr*)&addr, &addr_len);
        sockaddr_to_string(client_ip, (struct sockaddr*)&addr);
        log_error("No acceptable authentication method found for client at %s.", client_ip);
        if (sendFull(clientSocket, "\x05\xFF", 2, 0) < 0)
            return -1;

        log_info("Waiting for client to close the connection.");
        while (recv(clientSocket, receiveBuffer, READ_BUFFER_SIZE, 0) > 0) {}
        return -1;
    }
}

int handleRequest(int clientSocket, struct addrinfo** connectAddresses, int* dest_port, const char* authenticated_user) {
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

    log_info("Client asked to connect to: %s:%d", hostname, port);
    log_access(authenticated_user, "CONNECT_REQUEST", "Client requested to connect to %s:%d", hostname, port);

    // Store destination port for POP3 sniffing
    if (dest_port) {
        *dest_port = port;
    }

    char service[6] = {0};
    sprintf(service, "%d", port);

    int getAddrStatus = getaddrinfo(hostname, service, &addrHints, connectAddresses);
    if (getAddrStatus != 0) {
        log_error("getaddrinfo() failed for hostname '%s': %s", hostname, gai_strerror(getAddrStatus));

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
        log_error("connect_with_timeout failed: %s", strerror(errno));
        return -1;  // error
    } else if (poll_result == 0) {
        log_error("connect_with_timeout timed out after %dms", timeout_ms);
        return 0;   // timeout
    }
    
    // Chequeamos si la conexion fue exitosa
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0) {
        log_error("getsockopt failed: %s", strerror(errno));
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
        char flags_buffer[128];
        printFlags(aip, flags_buffer, sizeof(flags_buffer));
        log_info("Option %i: %s (%s %s) %s %s (Flags:%s)", aipIndex++, printFamily(aip), printType(aip), printProtocol(aip), aip->ai_canonname ? aip->ai_canonname : "-", printAddressPort(aip, addrBuf), flags_buffer);
        total_addresses++;
        if (aip->ai_family == AF_INET) ipv4_count++;
        else if (aip->ai_family == AF_INET6) ipv6_count++;
    }
    
    log_info("Attempting to connect to %d addresses (%d IPv4, %d IPv6)", 
           total_addresses, ipv4_count, ipv6_count);

    // Primero intentamos IPv6, luego IPv4
    int sock = -1;
    char addrBuffer[128];
    int attempt = 0;
    const char* last_error_type = "unknown";
    
    // Intentamos IPv6
    for (struct addrinfo* addr = *connectAddresses; addr != NULL && sock == -1; addr = addr->ai_next) {
        if (addr->ai_family != AF_INET6) continue;
        
        attempt++;
        log_info("Attempt %d/%d: Trying IPv6 %s", attempt, total_addresses, printAddressPort(addr, addrBuffer));
        
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0) {
            log_warn("Failed to create socket for %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
            last_error_type = "socket creation";
            continue;
        }
        
        int connect_result = connect_with_timeout(sock, addr->ai_addr, addr->ai_addrlen, CONNECTION_TIMEOUT_MS);
        if (connect_result == 1) {
            char flags_buffer[128];
            printFlags(addr, flags_buffer, sizeof(flags_buffer));
            log_info("Successfully connected to: %s (%s %s) %s %s (Flags:%s)", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf), flags_buffer);
            break;  // Exitoso
        } else {
            if (connect_result == 0) {
                log_info("Connection to %s timed out after %dms", printAddressPort(addr, addrBuffer), CONNECTION_TIMEOUT_MS);
                last_error_type = "timeout";
            } else {
                log_info("Connection to %s failed: %s", printAddressPort(addr, addrBuffer), strerror(errno));
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
            log_info("Attempt %d/%d: Trying IPv4 %s", attempt, total_addresses, printAddressPort(addr, addrBuffer));
            
            sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (sock < 0) {
                log_warn("Failed to create socket for %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
                last_error_type = "socket creation";
                continue;
            }
            
            int connect_result = connect_with_timeout(sock, addr->ai_addr, addr->ai_addrlen, CONNECTION_TIMEOUT_MS);
            if (connect_result == 1) {
                char flags_buffer[128];
                printFlags(addr, flags_buffer, sizeof(flags_buffer));
                log_info("Successfully connected to: %s (%s %s) %s %s (Flags:%s)", printFamily(addr), printType(addr), printProtocol(addr), addr->ai_canonname ? addr->ai_canonname : "-", printAddressPort(addr, addrBuf), flags_buffer);
                break;  // Exitoso
            } else {
                if (connect_result == 0) {
                    log_info("Connection to %s timed out after %dms", printAddressPort(addr, addrBuffer), CONNECTION_TIMEOUT_MS);
                    last_error_type = "timeout";
                } else {
                    log_info("Connection to %s failed: %s", printAddressPort(addr, addrBuffer), strerror(errno));
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
        log_error("Failed to connect to destination after trying %d addresses. Last error was: %s", 
               total_addresses, last_error_type);
        
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
        log_info("Remote socket bound at %s", addrBuffer);
    } else
        log_warn("Failed to getsockname() for remote socket");

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

int handleConnectionData(int clientSocket, int remoteSocket, const char* authenticated_user, int dest_port, struct socks5args* args) {
    ssize_t received;
    char receiveBuffer[4096];

    struct pollfd pollFds[2];
    pollFds[0].fd = clientSocket;
    pollFds[0].events = POLLIN;
    pollFds[0].revents = 0;
    pollFds[1].fd = remoteSocket;
    pollFds[1].events = POLLIN;
    pollFds[1].revents = 0;

    int alive = 1;
    do {
        int pollResult = poll(pollFds, 2, -1);
        if (pollResult < 0) {
            log_error("Poll returned %d: ", pollResult);
            perror(NULL);
            return -1;
        }

        for (int i = 0; i < 2 && alive; i++) {
            if (pollFds[i].revents == 0)
                continue;

            received = recv(pollFds[i].fd, receiveBuffer, sizeof(receiveBuffer), 0);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                } else {
                    log_error("recv() from %s failed: %s", i == 0 ? "client" : "remote server", strerror(errno));
                    alive = 0;
                }
            } else if (received == 0) {
                log_info("Connection closed by %s", i == 0 ? "client" : "remote server");
                alive = 0;
            } else {
                int otherSocket = pollFds[i].fd == clientSocket ? remoteSocket : clientSocket;

                // [PATCH POP3 SNIFFER]
                if (args && args->disectors_enabled && dest_port == 110 && pollFds[i].fd == clientSocket) {
                    char ip_origen[INET6_ADDRSTRLEN] = "unknown";
                    struct sockaddr_storage clientAddr;
                    socklen_t clientAddrLen = sizeof(clientAddr);
                    if (getpeername(clientSocket, (struct sockaddr*)&clientAddr, &clientAddrLen) == 0) {
                        if (clientAddr.ss_family == AF_INET) {
                            inet_ntop(AF_INET, &((struct sockaddr_in*)&clientAddr)->sin_addr, ip_origen, sizeof(ip_origen));
                        } else if (clientAddr.ss_family == AF_INET6) {
                            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&clientAddr)->sin6_addr, ip_origen, sizeof(ip_origen));
                        }
                    }
                    printf("[POP3 SNIFFER] Processing %zd bytes from %s\n", received, ip_origen);
                    pop3_sniffer_process((const uint8_t*)receiveBuffer, received, ip_origen);
                }
                // [FIN PATCH POP3 SNIFFER]

                ssize_t sent = sendFull(otherSocket, receiveBuffer, received, 0);
                if (sent != received) {
                    log_error("Failed to send all data: sent %zd/%zd bytes", sent, received);
                    alive = 0;
                } else {
                    if (authenticated_user && authenticated_user[0] != '\0') {
                        mgmt_update_user_stats(authenticated_user, sent, 0);
                    }
                }
            }
        }
    } while (alive);

    return 0;
}

int socks5_handle_greeting(int client_fd, struct socks5args *args, uint64_t connection_id) {
    uint8_t buffer[BUFFER_SIZE];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
    if (n <= 0) {
        log_error("Greeting failed (fd=%d, id=%llu): %s", client_fd, connection_id, n == 0 ? "closed" : strerror(errno));
        return -1;
    }

    if (buffer[0] != 0x05) {
        log_warn("Unsupported SOCKS version %d (fd=%d, id=%llu)", buffer[0], client_fd, connection_id);
        return -1; // SOCKS5
    }

    // respondemos con: version 5, método de autenticación 0x02 (username/password)
    uint8_t response[2] = {0x05, 0x02};
    send(client_fd, response, 2, 0);
    return STATE_AUTH;
}

int socks5_handle_auth(int client_fd, struct socks5args *args, uint64_t connection_id) {
    uint8_t buffer[BUFFER_SIZE];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
    if (n <= 0) {
        log_error("Auth failed (fd=%d, id=%llu): %s", client_fd, connection_id, n == 0 ? "closed" : strerror(errno));
        return -1;
    }

    if (buffer[0] != 0x01) {
        log_warn("Unsupported auth version %d (fd=%d, id=%llu)", buffer[0], client_fd, connection_id);
        return -1; // auth version
    }

    uint8_t ulen = buffer[1];
    char user[256] = {0};
    memcpy(user, &buffer[2], ulen);

    uint8_t plen = buffer[2 + ulen];
    char pass[256] = {0};
    memcpy(pass, &buffer[3 + ulen], plen);

    log_info("Auth attempt for user '%s' (fd=%d, id=%llu)", user, client_fd, connection_id);

    if (validateUser(user, pass, args)) {
        uint8_t response[2] = {0x01, 0x00}; // success
        send(client_fd, response, 2, 0);
        return STATE_REQUEST;
    } else {
        uint8_t response[2] = {0x01, 0x01}; // failure
        send(client_fd, response, 2, 0);
        return -1;
    }
}

int socks5_handle_request(int client_fd, struct socks5args *args, uint64_t connection_id) {
    uint8_t buffer[BUFFER_SIZE];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
    if (n <= 0) {
        log_error("Request failed (fd=%d, id=%llu): %s", client_fd, connection_id, n == 0 ? "closed" : strerror(errno));
        return -1;
    }

    if (buffer[0] != 0x05 || buffer[1] != 0x01) {
        log_warn("Unsupported request %d/%d (fd=%d, id=%llu)", buffer[0], buffer[1], client_fd, connection_id);
        return -1; // only CONNECT supported
    }

    uint8_t atyp = buffer[3];
    char dest_addr[256] = {0};
    uint16_t dest_port = 0;

    if (atyp == 0x01) { // IPv4
        struct in_addr ipv4_raw;
        memcpy(&ipv4_raw, &buffer[4], sizeof(ipv4_raw));
        inet_ntop(AF_INET, &ipv4_raw, dest_addr, sizeof(dest_addr));
        dest_port = ntohs(*(uint16_t*)&buffer[8]);
    } else if (atyp == 0x03) { // domain
        uint8_t len = buffer[4];
        memcpy(dest_addr, &buffer[5], len);
        dest_addr[len] = '\0';
        dest_port = ntohs(*(uint16_t*)&buffer[5 + len]);
    } else if (atyp == 0x04) { // IPv6
        struct in6_addr ipv6_raw;
        memcpy(&ipv6_raw, &buffer[4], sizeof(ipv6_raw));
        inet_ntop(AF_INET6, &ipv6_raw, dest_addr, sizeof(dest_addr));
        dest_port = ntohs(*(uint16_t*)&buffer[20]);
    } else {
        send_socks5_reply(client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
        return -1;
    }

    log_info("Client requested to connect to %s:%d (fd=%d, id=%llu)", dest_addr, dest_port, client_fd, connection_id);

    // conectamos
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", dest_port);
    if (getaddrinfo(dest_addr, port_str, &hints, &res) != 0) {
        log_error("Failed to resolve address: %s (fd=%d, id=%llu)", dest_addr, client_fd, connection_id);
        send_socks5_reply(client_fd, REPLY_HOST_UNREACHABLE);
        return -1;
    }

    int remote_fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        remote_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (remote_fd < 0) {
            continue; // try next address
        }
        if (connect(remote_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            // success
            break;
        }
        close(remote_fd);
        remote_fd = -1;
    }

    if (remote_fd < 0) {
        log_error("Failed to connect to %s:%d (fd=%d, id=%llu) using all resolved addresses", dest_addr, dest_port, client_fd, connection_id);
        freeaddrinfo(res);
        send_socks5_reply(client_fd, REPLY_CONNECTION_REFUSED);
        return -1;
    }

    log_info("Successfully connected to %s:%d (fd=%d, id=%llu)", dest_addr, dest_port, client_fd, connection_id);

    freeaddrinfo(res);

    // respondemos al cliente
    uint8_t response[10] = {0x05, 0x00, 0x00, 0x01};
    memset(&response[4], 0, 6); // BIND addr y port en 0
    send(client_fd, response, 10, 0);

    return remote_fd; // devolvemos fd remoto válido
}
