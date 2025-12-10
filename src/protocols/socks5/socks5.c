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
#include <pthread.h>

#include "socks5.h"
#include "../../utils/util.h"
#include "../../shared.h"
#include "../../utils/logger.h"

/* Tamaños varios */
#define READ_BUFFER_SIZE 2048
#define MAX_HOSTNAME_LENGTH 255

/* Helpers de IO “full” con pequeños timeouts para no quedar colgados */
static ssize_t recvFull(int fd, void* buf, size_t n, int flags) {
    size_t totalReceived = 0;
    int retries = 0;
    const int maxRetries = 100;

    while (totalReceived < n && retries < maxRetries) {
        ssize_t nowReceived = recv(fd, (char*)buf + totalReceived, n - totalReceived, flags);

        if (nowReceived < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
                int poll_result = poll(&pfd, 1, 5000); // 5s

                if (poll_result < 0) {
                    log_error("poll() in recvFull: %s", strerror(errno));
                    return -1;
                } else if (poll_result == 0) {
                    log_error("recv() timeout after 5 seconds");
                    return -1;
                } else {
                    retries++;
                    continue;
                }
            } else {
                log_error("recv(): %s", strerror(errno));
                return -1;
            }
        } else if (nowReceived == 0) {
            if (totalReceived == 0) {
                log_error("Connection closed by peer before any data received");
                return -1;
            } else {
                log_warn("Connection closed by peer, partial data received: %zu/%zu bytes",
                         totalReceived, n);
                return totalReceived;
            }
        } else {
            totalReceived += nowReceived;
            retries = 0;
        }
    }

    if (retries >= maxRetries) {
        log_error("recvFull() exceeded maximum retries");
        return -1;
    }

    return totalReceived;
}

static ssize_t sendFull(int fd, const void* buf, size_t n, int flags) {
    size_t totalSent = 0;
    int retries = 0;
    const int maxRetries = 100;

    while (totalSent < n && retries < maxRetries) {
        ssize_t nowSent = send(fd, (const char*)buf + totalSent, n - totalSent, flags);

        if (nowSent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
                int poll_result = poll(&pfd, 1, 5000); // 5s

                if (poll_result < 0) {
                    log_error("poll() in sendFull: %s", strerror(errno));
                    return -1;
                } else if (poll_result == 0) {
                    log_error("send() timeout after 5 seconds");
                    return -1;
                } else {
                    retries++;
                    continue;
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

/* ---- Validación de usuario (archivo + shared memory + args) ---- */

int validateUser(const char* username, const char* password, struct socks5args* args) {
    if (!username || !password) {
        return 0;
    }

    /* 1) auth.db */
    FILE* file = fopen("auth.db", "r");
    if (file != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), file)) {
            char* db_user = strtok(line, ":");
            char* db_pass = strtok(NULL, "\n");
            if (db_user && db_pass) {
                if (strcmp(username, db_user) == 0 && strcmp(password, db_pass) == 0) {
                    fclose(file);
                    log_access(username, "AUTH_SUCCESS", "User authenticated successfully (auth.db)");
                    return 1;
                }
            }
        }
        fclose(file);
    }

    /* 2) memoria compartida */
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

    /* 3) usuarios de línea de comandos (args) */
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

/* ---- Respuestas genéricas SOCKS5 ---- */

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

    ssize_t n = sendFull(client_fd, response, sizeof(response), 0);
    return n == (ssize_t)sizeof(response) ? 0 : -1;
}

/* ---- GREETING ----
 * Lee VER, NMETHODS, METHODS y responde con USERPASS (0x02).
 * Devuelve 1 (STATE_AUTH) o <0 en error.
 */

int socks5_handle_greeting(int client_fd,
                           struct socks5args *args,
                           uint64_t connection_id) {
    (void)args; // por ahora no lo usamos acá

    uint8_t hdr[2];
    ssize_t n = recvFull(client_fd, hdr, 2, 0);
    if (n <= 0) {
        log_error("Greeting failed (fd=%d, id=%llu): %s",
                  client_fd, (unsigned long long)connection_id,
                  n == 0 ? "closed" : strerror(errno));
        return -1;
    }

    if (hdr[0] != SOCKS_VERSION) {
        log_warn("Unsupported SOCKS version %d (fd=%d, id=%llu)",
                 hdr[0], client_fd, (unsigned long long)connection_id);
        return -1;
    }

    uint8_t nmethods = hdr[1];
    uint8_t methods[256];
    if (nmethods == 0) {
        log_error("Client sent 0 methods (fd=%d, id=%llu)",
                  client_fd, (unsigned long long)connection_id);
        return -1;
    }

    n = recvFull(client_fd, methods, nmethods, 0);
    if (n <= 0) {
        log_error("Failed to read methods (fd=%d, id=%llu): %s",
                  client_fd, (unsigned long long)connection_id,
                  n == 0 ? "closed" : strerror(errno));
        return -1;
    }

    log_info("Client (fd=%d, id=%llu) offered %u methods",
             client_fd, (unsigned long long)connection_id, nmethods);

    /* Por simplicidad: siempre pedimos USERPASS (0x02).
     * (curl soporta esto sin problemas usando --proxy-user)
     */
    uint8_t resp[2] = { SOCKS_VERSION, SOCKS5_AUTH_USERPASS };
    if (sendFull(client_fd, resp, 2, 0) < 0) {
        log_error("Failed to send greeting response (fd=%d, id=%llu)",
                  client_fd, (unsigned long long)connection_id);
        return -1;
    }

    return 1; // STATE_AUTH
}

/* ---- AUTH ----
 * Sub-negociación USER/PASS.
 * Devuelve 2 (STATE_REQUEST) o <0 si falla.
 */

int socks5_handle_auth(int client_fd,
                       struct socks5args *args,
                       uint64_t connection_id) {
    uint8_t hdr[2];
    ssize_t received = recvFull(client_fd, hdr, 2, 0);
    if (received < 0) {
        log_error("Failed to receive username/password auth header");
        return -1;
    }

    if (hdr[0] != 0x01) {
        log_error("Invalid username/password auth version: %d", hdr[0]);
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }

    int usernameLen = hdr[1];
    if (usernameLen <= 0 || usernameLen > 255) {
        log_error("Invalid username length: %d", usernameLen);
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }

    char username[256];
    received = recvFull(client_fd, username, usernameLen, 0);
    if (received < 0) {
        log_error("Failed to receive username");
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }
    username[usernameLen] = '\0';

    uint8_t pwdLenBuf[1];
    received = recvFull(client_fd, pwdLenBuf, 1, 0);
    if (received < 0) {
        log_error("Failed to receive password length");
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }

    int passwordLen = pwdLenBuf[0];
    if (passwordLen <= 0 || passwordLen > 255) {
        log_error("Invalid password length: %d", passwordLen);
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }

    char password[256];
    received = recvFull(client_fd, password, passwordLen, 0);
    if (received < 0) {
        log_error("Failed to receive password");
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }
    password[passwordLen] = '\0';

    log_info("Authentication attempt (fd=%d, id=%llu): username='%s'",
             client_fd, (unsigned long long)connection_id, username);

    if (validateUser(username, password, args)) {
        if (sendFull(client_fd, "\x01\x00", 2, 0) < 0) {
            log_error("Failed to send auth success response");
            return -1;
        }
        return 2; // STATE_REQUEST
    } else {
        sendFull(client_fd, "\x01\x01", 2, 0);
        return -1;
    }
}

/* ---- REQUEST + RESOLUCIÓN + CONNECT ----
 * Se llama desde un thread. Bloquea, pero ya no traba el select().
 * Devuelve fd remoto >=0 en éxito, <0 en error.
 */

int socks5_handle_request(int client_fd,
                          struct socks5args *args,
                          uint64_t connection_id,
                          uint16_t *dest_port_out) {
    (void)args; // por ahora no usamos nada extra de args acá

    uint8_t hdr[4];
    ssize_t received = recvFull(client_fd, hdr, 4, 0);
    if (received < 0) {
        log_error("Request failed (fd=%d, id=%llu): header read error",
                  client_fd, (unsigned long long)connection_id);
        return -1;
    }

    uint8_t ver = hdr[0];
    uint8_t cmd = hdr[1];
    uint8_t atyp = hdr[3];

    if (ver != SOCKS_VERSION || cmd != 0x01) {  // solo soportamos CONNECT
        log_warn("Unsupported request %d/%d (fd=%d, id=%llu)",
                 ver, cmd, client_fd, (unsigned long long)connection_id);
        send_socks5_reply(client_fd, REPLY_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    char dest_addr[256] = {0};
    uint16_t dest_port = 0;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (atyp == 0x01) {
        /* IPv4 */
        struct in_addr addr;
        received = recvFull(client_fd, &addr, sizeof(addr), 0);
        if (received < 0) return -1;

        uint16_t portBuf;
        received = recvFull(client_fd, &portBuf, sizeof(portBuf), 0);
        if (received < 0) return -1;

        dest_port = ntohs(portBuf);
        inet_ntop(AF_INET, &addr, dest_addr, sizeof(dest_addr));
    } else if (atyp == 0x03) {
        /* Dominio */
        uint8_t len;
        received = recvFull(client_fd, &len, 1, 0);
        if (received < 0) return -1;

        if (len == 0 || len > 255) {
            send_socks5_reply(client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
            return -1;
        }

        received = recvFull(client_fd, dest_addr, len, 0);
        if (received < 0) return -1;
        dest_addr[len] = '\0';

        uint16_t portBuf;
        received = recvFull(client_fd, &portBuf, sizeof(portBuf), 0);
        if (received < 0) return -1;

        dest_port = ntohs(portBuf);
    } else if (atyp == 0x04) {
        /* IPv6 */
        struct in6_addr addr6;
        received = recvFull(client_fd, &addr6, sizeof(addr6), 0);
        if (received < 0) return -1;

        uint16_t portBuf;
        received = recvFull(client_fd, &portBuf, sizeof(portBuf), 0);
        if (received < 0) return -1;

        dest_port = ntohs(portBuf);
        inet_ntop(AF_INET6, &addr6, dest_addr, sizeof(dest_addr));
    } else {
        send_socks5_reply(client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
        return -1;
    }

    log_info("Client requested to connect to %s:%u (fd=%d, id=%llu)",
             dest_addr, dest_port, client_fd, (unsigned long long)connection_id);

    if (dest_port_out) {
        *dest_port_out = dest_port;
    }

    char service[6];
    snprintf(service, sizeof(service), "%u", dest_port);

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(dest_addr, service, &hints, &res);
    if (gai != 0) {
        log_error("getaddrinfo() failed for hostname '%s': %s",
                  dest_addr, gai_strerror(gai));
        send_socks5_reply(client_fd, REPLY_HOST_UNREACHABLE);
        return -1;
    }

    int remote_fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        remote_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (remote_fd < 0) {
            continue;
        }

        if (connect(remote_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            /* éxito */
            break;
        }

        close(remote_fd);
        remote_fd = -1;
    }

    if (remote_fd < 0) {
        log_error("Failed to connect to %s:%u (fd=%d, id=%llu)",
                  dest_addr, dest_port, client_fd, (unsigned long long)connection_id);
        freeaddrinfo(res);
        send_socks5_reply(client_fd, REPLY_CONNECTION_REFUSED);
        return -1;
    }

    freeaddrinfo(res);

    /* Respuesta de éxito al cliente: VER REP RSV ATYP BND.ADDR BND.PORT
     * Para simplificar, devolvemos 0.0.0.0:0 (como hace send_socks5_reply en SUCCEEDED).
     */
    uint8_t resp[10] = {
        SOCKS_VERSION,
        REPLY_SUCCEEDED,
        0x00,
        0x01, /* IPv4 dummy */
        0x00, 0x00, 0x00, 0x00, /* 0.0.0.0 */
        0x00, 0x00              /* port 0 */
    };

    if (sendFull(client_fd, resp, sizeof(resp), 0) < 0) {
        log_error("Failed to send success reply to client");
        close(remote_fd);
        return -1;
    }

    log_info("Successfully connected to %s:%u (fd=%d, remote_fd=%d, id=%llu)",
             dest_addr, dest_port, client_fd, remote_fd, (unsigned long long)connection_id);

    return remote_fd;
}
