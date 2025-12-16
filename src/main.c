#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <inttypes.h>

#include "protocols/socks5/socks5.h"
#include "protocols/pop3/pop3_sniffer.h"
#include "utils/logger.h"
#include "utils/util.h"
#include "utils/args.h"
#include "shared.h"

#define MAX_CLIENTS 1024
#define MAX_PENDING_CONNECTION_REQUESTS 128

typedef enum {
    STATE_GREETING,
    STATE_AUTH,
    STATE_REQUEST,
    STATE_CONNECTING,
    STATE_RELAYING,
    STATE_DONE,
    STATE_ERROR
} client_state;

typedef struct {
    char data[MAX_BUFFER_CAPACITY];
    size_t len;
    size_t offset;
} pending_buffer_t;

typedef struct {
    int client_fd;
    uint64_t connection_id;
    int remote_fd;
    int dest_port;
    client_state state;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    pending_buffer_t pending_to_remote;
    pending_buffer_t pending_to_client;
} client_t;

client_t clients[MAX_CLIENTS];
static size_t relay_buffer_size = DEFAULT_BUFFER_SIZE;

static void reset_pending(pending_buffer_t *pending) {
    pending->len = 0;
    pending->offset = 0;
}

static int recompute_fdmax(int server_fd, int mgmt_fd) {
    int max_fd = server_fd > mgmt_fd ? server_fd : mgmt_fd;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].client_fd > max_fd) max_fd = clients[i].client_fd;
        if (clients[i].remote_fd > max_fd) max_fd = clients[i].remote_fd;
    }
    return max_fd;
}

static void stop_tracking_fd(fd_set *set, int fd) {
    if (fd >= 0) {
        FD_CLR(fd, set);
    }
}

static void track_fd(fd_set *set, int fd) {
    if (fd >= 0) {
        FD_SET(fd, set);
    }
}

static void *mgmt_thread(void *arg) {
    int mgmt_client_fd = *(int *)arg;
    free(arg);

    int flags = fcntl(mgmt_client_fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(mgmt_client_fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    mgmt_handle_client(mgmt_client_fd);
    close(mgmt_client_fd);
    return NULL;
}

void cleanup_handler(int sig) {
    printf("[SIG] Caught signal %d, cleaning up and exiting.\n", sig);
    log_info("Signal %d received. Cleaning up...", sig);
    mgmt_cleanup_shared_memory();
    exit(0);
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    printf("[DBG] Set non-blocking mode on fd=%d\n", fd);
}

void remove_client(int i, fd_set *read_master, fd_set *write_master) {
    if (clients[i].client_fd != -1) {
        printf("[DBG] Closing client fd=%d\n", clients[i].client_fd);
        close(clients[i].client_fd);
        stop_tracking_fd(read_master, clients[i].client_fd);
        stop_tracking_fd(write_master, clients[i].client_fd);
    }
    if (clients[i].remote_fd != -1) {
        printf("[DBG] Closing remote fd=%d\n", clients[i].remote_fd);
        close(clients[i].remote_fd);
        stop_tracking_fd(read_master, clients[i].remote_fd);
        stop_tracking_fd(write_master, clients[i].remote_fd);
    }
    mgmt_update_stats(0, -1);
    clients[i].client_fd = -1;
    clients[i].remote_fd = -1;
    clients[i].state = STATE_DONE;
    reset_pending(&clients[i].pending_to_remote);
    reset_pending(&clients[i].pending_to_client);
}

static bool pending_has_data(const pending_buffer_t *pending) {
    return pending->len > pending->offset;
}

static int flush_pending(int to_fd, int resume_fd, pending_buffer_t *pending,
                         fd_set *read_master, fd_set *write_master) {
    while (pending_has_data(pending)) {
        ssize_t n = send(to_fd, pending->data + pending->offset,
                         pending->len - pending->offset, 0);
        if (n > 0) {
            pending->offset += (size_t)n;
            mgmt_update_stats((uint64_t)n, 0);
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            track_fd(write_master, to_fd);
            return 0;
        } else {
            return -1;
        }
    }

    reset_pending(pending);
    stop_tracking_fd(write_master, to_fd);
    if (resume_fd >= 0) {
        track_fd(read_master, resume_fd);
    }
    return 1;
}

int create_server_socket(int port) {
    printf("[INF] Creating server socket on port %d...\n", port);
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;
    if (listen(sock, MAX_PENDING_CONNECTION_REQUESTS) < 0) return -1;

    return sock;
}

int find_available_client_slot(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].client_fd == -1) return i;
    }
    return -1;
}

static void relay_data(int from_fd, int to_fd, int client_index, struct socks5args *args,
                       pending_buffer_t *pending, fd_set *read_master, fd_set *write_master) {
    char buffer[MAX_BUFFER_CAPACITY];
    const bool dissectors_active = args && args->disectors_enabled && mgmt_are_dissectors_enabled();
    if (pending_has_data(pending)) {
        flush_pending(to_fd, from_fd, pending, read_master, write_master);
        if (pending_has_data(pending)) {
            return;
        }
    }
    size_t chunk = relay_buffer_size;
    if (chunk > MAX_BUFFER_CAPACITY) {
        chunk = MAX_BUFFER_CAPACITY;
    }
    ssize_t nread = recv(from_fd, buffer, chunk, 0);
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        printf("[ERR] Recv error in relay (client=%d): %s\n", clients[client_index].client_fd, strerror(errno));
        log_error("Recv error in relay (client=%d)", clients[client_index].client_fd);
        clients[client_index].state = STATE_ERROR;
        return;
    }

    if (nread == 0) {
        printf("[DBG] Connection closed in relay (client=%d)\n", clients[client_index].client_fd);
        log_info("Connection closed in relay (client=%d)", clients[client_index].client_fd);
        clients[client_index].state = STATE_DONE;
        return;
    }

    if (dissectors_active && clients[client_index].dest_port == 110 && from_fd == clients[client_index].client_fd) {
        char ip_origen[INET6_ADDRSTRLEN] = "unknown";
        struct sockaddr_storage clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        if (getpeername(clients[client_index].client_fd, (struct sockaddr*)&clientAddr, &clientAddrLen) == 0) {
            if (clientAddr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in*)&clientAddr)->sin_addr, ip_origen, sizeof(ip_origen));
            } else if (clientAddr.ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)&clientAddr)->sin6_addr, ip_origen, sizeof(ip_origen));
            }
        }
        pop3_sniffer_process((const uint8_t *)buffer, (size_t)nread, ip_origen);
    }

    ssize_t total_written = 0;
    while (total_written < nread) {
        ssize_t nwritten = send(to_fd, buffer + total_written, nread - total_written, 0);
        if (nwritten < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                size_t pending_len = (size_t)(nread - total_written);
                if (pending_len > MAX_BUFFER_CAPACITY) {
                    pending_len = MAX_BUFFER_CAPACITY;
                }
                memcpy(pending->data, buffer + total_written, pending_len);
                pending->len = pending_len;
                pending->offset = 0;
                track_fd(write_master, to_fd);
                stop_tracking_fd(read_master, from_fd);
                return;
            }
            printf("[ERR] Send error in relay (client=%d): %s\n", clients[client_index].client_fd, strerror(errno));
            log_error("Send error in relay (client=%d)", clients[client_index].client_fd);
            clients[client_index].state = STATE_ERROR;
            return;
        }
        total_written += nwritten;
        mgmt_update_stats(nwritten, 0);
    }
}

int main(int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);
    logger_init(LOG_INFO, "metrics.log");
    atexit(logger_close);

    // Inicializar memoria compartida
    if (mgmt_init_shared_memory() < 0) {
        log_fatal("Failed to initialize shared memory");
        return 1;
    }

    if (!args.disectors_enabled) {
        log_info("POP3 dissectors disabled via CLI flag (-N). No credentials will be captured.");
    } else if (!mgmt_are_dissectors_enabled()) {
        log_info("POP3 dissectors disabled via management config. Use the client to enable them.");
    } else {
        log_info("POP3 dissectors enabled. Captures stored in pop3_credentials.log");
    }

    int configured_buffer = mgmt_get_buffer_size();
    if (configured_buffer < MIN_BUFFER_SIZE) {
        configured_buffer = DEFAULT_BUFFER_SIZE;
    } else if (configured_buffer > MAX_BUFFER_CAPACITY) {
        configured_buffer = MAX_BUFFER_CAPACITY;
    }
    relay_buffer_size = (size_t)configured_buffer;

    printf("[INF] Iniciando servidor SOCKS5...\n");

    int server_fd = create_server_socket(args.socks_port);
    if (server_fd < 0) {
        perror("server socket");
        return 1;
    }
    set_nonblocking(server_fd);

    // Iniciar servidor de gestion
    int mgmt_fd = mgmt_server_start(args.mng_port);
        if (mgmt_fd < 0) {
        log_error("No se pudo iniciar el servidor de gestión");
        return 1;
    }
    // Trabajaremos la gestión en el mismo loop multiplexado (un solo hilo).
    set_nonblocking(mgmt_fd);


    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].client_fd = -1;
        clients[i].remote_fd = -1;
        clients[i].state = STATE_DONE;
    }

    fd_set read_master, write_master, read_set, write_set;
    FD_ZERO(&read_master);
    FD_ZERO(&write_master);
    FD_SET(server_fd, &read_master);
    FD_SET(mgmt_fd, &read_master);
    int fdmax = (server_fd > mgmt_fd) ? server_fd : mgmt_fd;

    signal(SIGINT, cleanup_handler);

    while (1) {
        int desired_buffer = mgmt_get_buffer_size();
        if (desired_buffer < MIN_BUFFER_SIZE) {
            desired_buffer = DEFAULT_BUFFER_SIZE;
        } else if (desired_buffer > MAX_BUFFER_CAPACITY) {
            desired_buffer = MAX_BUFFER_CAPACITY;
        }
        if ((size_t)desired_buffer != relay_buffer_size) {
            relay_buffer_size = (size_t)desired_buffer;
            log_info("Relay buffer size set to %d bytes", desired_buffer);
        }

        read_set = read_master;
        write_set = write_master;

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ready = select(fdmax + 1, &read_set, &write_set, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (ready == 0) {
            continue;
        }

        if (FD_ISSET(server_fd, &read_set)) {
            struct sockaddr_storage client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
            if (client_fd >= 0) {
                set_nonblocking(client_fd);
                int i = find_available_client_slot();
                if (i >= 0) {
                    clients[i].client_fd = client_fd;
                    clients[i].connection_id = mgmt_get_next_connection_id();
                    clients[i].remote_fd = -1;
                    clients[i].dest_port = 0;
                    clients[i].state = STATE_GREETING;
                    clients[i].addr = client_addr;
                    clients[i].addr_len = addrlen;
                    reset_pending(&clients[i].pending_to_remote);
                    reset_pending(&clients[i].pending_to_client);
                    track_fd(&read_master, client_fd); 
                    stop_tracking_fd(&write_master, client_fd);
                    if (client_fd > fdmax) fdmax = client_fd;
                    printf("[INF] Accepted new client (fd=%d, id=%" PRIu64 ")\n", client_fd, clients[i].connection_id);
                    log_info("Accepted new client (fd=%d, id=%" PRIu64 ")", client_fd, clients[i].connection_id);
                    mgmt_update_stats(0, 1);
                } else {
                    printf("[ERR] Too many clients, rejecting fd=%d\n", client_fd);
                    log_error("Too many clients");
                    close(client_fd);
                }
            }
        }

        if (FD_ISSET(mgmt_fd, &read_set)) {
            int mgmt_client_fd = accept(mgmt_fd, NULL, NULL);
            if (mgmt_client_fd >= 0) {
                int *fd_copy = malloc(sizeof(int));
                if (fd_copy == NULL) {
                    close(mgmt_client_fd);
                } else {
                    *fd_copy = mgmt_client_fd;
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, mgmt_thread, fd_copy) == 0) {
                        pthread_detach(tid);
                    } else {
                        free(fd_copy);
                        close(mgmt_client_fd);
                    }
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int cfd = clients[i].client_fd;
            if (cfd == -1) continue;

            if (clients[i].state == STATE_DONE || clients[i].state == STATE_ERROR) {
                remove_client(i, &read_master, &write_master);
                fdmax = recompute_fdmax(server_fd, mgmt_fd);
                continue;
            }

            if (clients[i].state == STATE_RELAYING) {
                if (clients[i].remote_fd != -1 && pending_has_data(&clients[i].pending_to_remote) &&
                    FD_ISSET(clients[i].remote_fd, &write_set)) {
                    if (flush_pending(clients[i].remote_fd, cfd, &clients[i].pending_to_remote,
                                      &read_master, &write_master) < 0) {
                        clients[i].state = STATE_ERROR;
                    }
                }
                if (pending_has_data(&clients[i].pending_to_client) && FD_ISSET(cfd, &write_set)) {
                    if (flush_pending(cfd, clients[i].remote_fd, &clients[i].pending_to_client,
                                      &read_master, &write_master) < 0) {
                        clients[i].state = STATE_ERROR;
                    }
                }
            }

            bool client_can_read = FD_ISSET(cfd, &read_set);
            bool remote_can_read = clients[i].remote_fd != -1 && FD_ISSET(clients[i].remote_fd, &read_set);

            if (!client_can_read && !remote_can_read) {
                continue;
            }

            switch (clients[i].state) {
                case STATE_GREETING:
                    if (!client_can_read) break;
                    printf("[DBG] Handling GREETING for fd=%d\n", cfd);
                    log_info("Handling GREETING for fd=%d, id=%" PRIu64, cfd, clients[i].connection_id);
                    {
                        int res = socks5_handle_greeting(cfd, &args, clients[i].connection_id);
                        if (res < 0) {
                            clients[i].state = STATE_ERROR;
                        } else {
                            clients[i].state = (client_state)res;
                        }
                    }
                    break;
                case STATE_AUTH:
                    if (!client_can_read) break;
                    printf("[DBG] Handling AUTH for fd=%d\n", cfd);
                    log_info("Handling AUTH for fd=%d, id=%" PRIu64, cfd, clients[i].connection_id);
                    {
                        int res = socks5_handle_auth(cfd, &args, clients[i].connection_id);
                        if (res < 0) {
                            clients[i].state = STATE_ERROR;
                        } else {
                            clients[i].state = (client_state)res;
                        }
                    }
                    break;
                case STATE_REQUEST:
                    if (!client_can_read) break;
                    printf("[DBG] Handling REQUEST for fd=%d\n", cfd);
                    log_info("Handling REQUEST for fd=%d, id=%" PRIu64, cfd, clients[i].connection_id);
                    clients[i].remote_fd = socks5_handle_request(cfd, &args, clients[i].connection_id, &clients[i].dest_port);
                    if (clients[i].remote_fd >= 0) {
                        set_nonblocking(clients[i].remote_fd);
                        track_fd(&read_master, clients[i].remote_fd);
                        stop_tracking_fd(&write_master, clients[i].remote_fd);
                        if (clients[i].remote_fd > fdmax) fdmax = clients[i].remote_fd;
                        clients[i].state = STATE_RELAYING;
                    } else {
                        clients[i].state = STATE_ERROR;
                    }
                    break;
                case STATE_RELAYING:
                    if (client_can_read && clients[i].remote_fd != -1) {
                        relay_data(cfd, clients[i].remote_fd, i, &args,
                                   &clients[i].pending_to_remote, &read_master, &write_master);
                    }
                    if (remote_can_read) {
                        relay_data(clients[i].remote_fd, cfd, i, &args,
                                   &clients[i].pending_to_client, &read_master, &write_master);
                    }
                    break;
                default:
                    break;
            }

            if (clients[i].state == STATE_ERROR || clients[i].state == STATE_DONE) {
                remove_client(i, &read_master, &write_master);
                fdmax = recompute_fdmax(server_fd, mgmt_fd);
            }
        }
    }

    printf("[INF] Server exiting...\n");
    close(server_fd);
    close(mgmt_fd);
    mgmt_cleanup_shared_memory();
    return 0;
}
