#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdint.h>

#include "protocols/socks5/socks5.h"
#include "utils/logger.h"
#include "utils/util.h"
#include "utils/args.h"
#include "shared.h"

#define MAX_CLIENTS 1024
#define BUFFER_SIZE 4096
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
    int client_fd;
    uint64_t connection_id;
    int remote_fd;
    client_state state;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    char buffer[BUFFER_SIZE];
    int buffer_len;
    int closed;
    int resolving;
} client_t;

client_t clients[MAX_CLIENTS];

/* Pipe para comunicar threads de resolución DNS con el loop principal. */
static int dns_pipe_fds[2] = { -1, -1 };

typedef struct {
    int client_index;
    int remote_fd;
} dns_result_t;

typedef struct {
    int client_index;
    int client_fd;
    struct socks5args *args;
    uint64_t connection_id;
} resolve_task_t;

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

void remove_client(int i, fd_set *master_set) {
    if (clients[i].client_fd != -1) {
        printf("[DBG] Closing client fd=%d\n", clients[i].client_fd);
        close(clients[i].client_fd);
        FD_CLR(clients[i].client_fd, master_set);
    }
    if (clients[i].remote_fd != -1) {
        printf("[DBG] Closing remote fd=%d\n", clients[i].remote_fd);
        close(clients[i].remote_fd);
        FD_CLR(clients[i].remote_fd, master_set);
    }
    mgmt_update_stats(0, -1);
    clients[i].client_fd   = -1;
    clients[i].remote_fd   = -1;
    clients[i].state       = STATE_DONE;
    clients[i].resolving   = 0;
}

/* Thread que hace la resolución bloqueante (socks5_handle_request) */
static void *resolver_thread(void *arg) {
    resolve_task_t *task = (resolve_task_t *)arg;
    dns_result_t res;
    res.client_index = task->client_index;

    /* socks5_handle_request ahora recibe un puntero a dest_port_out */
    uint16_t remote_port = 0;
    int remote_fd = socks5_handle_request(task->client_fd,
                                          task->args,
                                          task->connection_id,
                                          &remote_port);
    res.remote_fd = remote_fd;

    if (dns_pipe_fds[1] != -1) {
        ssize_t n = write(dns_pipe_fds[1], &res, sizeof(res));
        (void)n;
    }

    free(task);
    return NULL;
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

/* Cuenta cuántos clientes activos hay actualmente */
int count_active_clients(void) {
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].client_fd != -1) {
            count++;
        }
    }
    return count;
}

void relay_data(int from_fd, int to_fd, int client_index) {
    char buffer[BUFFER_SIZE];
    ssize_t nread = recv(from_fd, buffer, sizeof(buffer), 0);
    if (nread <= 0) {
        printf("[DBG] Connection closed in relay (client=%d)\n", clients[client_index].client_fd);
        log_info("Connection closed in relay (client=%d)", clients[client_index].client_fd);
        clients[client_index].state = STATE_DONE;
        return;
    }
    ssize_t nwritten = send(to_fd, buffer, nread, 0);
    if (nwritten > 0) {
        mgmt_update_stats(nwritten, 0);
    }
    if (nwritten < 0) {
        printf("[ERR] Send error in relay (client=%d)\n", clients[client_index].client_fd);
        log_error("Send error in relay (client=%d)", clients[client_index].client_fd);
        clients[client_index].state = STATE_ERROR;
    }
}

int main(int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);
    logger_init(LOG_INFO, "metrics.log");
    atexit(logger_close);

    if (mgmt_init_shared_memory() < 0) {
        log_fatal("Failed to initialize shared memory");
        return 1;
    }

    printf("[INF] Iniciando servidor SOCKS5...\n");

    int server_fd = create_server_socket(args.socks_port);
    if (server_fd < 0) {
        perror("server socket");
        return 1;
    }
    set_nonblocking(server_fd);

    // Iniciar servidor de gestión (se maneja en un hilo separado)
    int mgmt_fd = mgmt_server_start(args.mng_port);
    if (mgmt_fd < 0) {
        log_error("No se pudo iniciar el servidor de gestión");
        return 1;
    }

    pthread_t mgmt_thread;
    if (pthread_create(&mgmt_thread, NULL, mgmt_accept_loop, &mgmt_fd) != 0) {
        perror("pthread_create mgmt_thread");
        return 1;
    }
    pthread_detach(mgmt_thread);

    // Crear pipe para resultados de resolución DNS
    if (pipe(dns_pipe_fds) < 0) {
        perror("dns pipe");
        return 1;
    }
    set_nonblocking(dns_pipe_fds[0]);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].client_fd   = -1;
        clients[i].remote_fd   = -1;
        clients[i].state       = STATE_DONE;
        clients[i].resolving   = 0;
    }

    fd_set master_set, read_set;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    FD_SET(dns_pipe_fds[0], &master_set);

    int fdmax = server_fd;
    if (dns_pipe_fds[0] > fdmax) fdmax = dns_pipe_fds[0];

    signal(SIGINT, cleanup_handler);

    while (1) {
        read_set = master_set;

        /* OJO: sólo monitoreamos lecturas (writefds = NULL) para evitar busy loop */
        if (select(fdmax + 1, &read_set, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        /* 1) Resultados de resolución DNS desde threads */
        if (FD_ISSET(dns_pipe_fds[0], &read_set)) {
            dns_result_t res;
            while (1) {
                ssize_t n = read(dns_pipe_fds[0], &res, sizeof(res));
                if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break;
                }
                if (n != sizeof(res)) {
                    break;
                }

                int idx = res.client_index;
                if (idx < 0 || idx >= MAX_CLIENTS) {
                    if (res.remote_fd >= 0) close(res.remote_fd);
                    continue;
                }

                client_t *cl = &clients[idx];
                cl->resolving = 0;

                if (cl->client_fd == -1) {
                    if (res.remote_fd >= 0) close(res.remote_fd);
                    continue;
                }

                if (res.remote_fd >= 0) {
                    cl->remote_fd = res.remote_fd;
                    set_nonblocking(cl->remote_fd);
                    FD_SET(cl->remote_fd, &master_set);
                    if (cl->remote_fd > fdmax) fdmax = cl->remote_fd;
                    cl->state = STATE_RELAYING;
                    printf("[INF] Resolution done for fd=%d, remote_fd=%d, switching to RELAYING\n",
                           cl->client_fd, cl->remote_fd);
                } else {
                    cl->state = STATE_ERROR;
                    printf("[ERR] Resolution failed for fd=%d, setting STATE_ERROR\n", cl->client_fd);
                }
            }
        }

        /* 2) Nuevas conexiones de clientes SOCKS */
        if (FD_ISSET(server_fd, &read_set)) {
            struct sockaddr_storage client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
            if (client_fd >= 0) {
                set_nonblocking(client_fd);

                // 1) Chequeamos cuántos clientes activos hay
                int active = count_active_clients();

                // 2) Obtenemos el límite configurado desde el módulo de management
                int max_allowed = mgmt_get_max_clients();
                if (max_allowed <= 0 || max_allowed > MAX_CLIENTS) {
                    max_allowed = MAX_CLIENTS; // fallback razonable
                }

                if (active >= max_allowed) {
                    // No aceptamos más conexiones aunque haya slots en el array
                    printf("[ERR] Max clients reached (%d), rejecting fd=%d\n", max_allowed, client_fd);
                    log_error("Max clients reached (%d), rejecting fd=%d", max_allowed, client_fd);
                    close(client_fd);
                } else {
                    // 3) Reutilizamos la lógica existente de slots
                    int i = find_available_client_slot();
                    if (i >= 0) {
                        clients[i].client_fd       = client_fd;
                        clients[i].connection_id   = mgmt_get_next_connection_id();
                        clients[i].remote_fd       = -1;
                        clients[i].state           = STATE_GREETING;
                        clients[i].addr            = client_addr;
                        clients[i].addr_len        = addrlen;
                        clients[i].buffer_len      = 0;
                        clients[i].closed          = 0;
                        clients[i].resolving       = 0;
                        FD_SET(client_fd, &master_set);
                        if (client_fd > fdmax) fdmax = client_fd;
                        printf("[INF] Accepted new client (fd=%d, id=%llu)\n",
                               client_fd, (unsigned long long)clients[i].connection_id);
                        log_info("Accepted new client (fd=%d, id=%llu)",
                                 client_fd, (unsigned long long)clients[i].connection_id);
                        mgmt_update_stats(0, 1);
                    } else {
                        printf("[ERR] Too many clients (no slot), rejecting fd=%d\n", client_fd);
                        log_error("Too many clients (no slot)");
                        close(client_fd);
                    }
                }
            }
        }

        /* 3) Manejo de clientes ya conectados */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int cfd = clients[i].client_fd;
            if (cfd == -1) continue;

            int r_remote = (clients[i].remote_fd != -1 &&
                            FD_ISSET(clients[i].remote_fd, &read_set));
            int r_client = FD_ISSET(cfd, &read_set);

            if (!r_remote && !r_client) {
                continue;
            }

            switch (clients[i].state) {
                case STATE_GREETING:
                    printf("[DBG] Handling GREETING for fd=%d\n", cfd);
                    log_info("Handling GREETING for fd=%d, id=%llu",
                             cfd, (unsigned long long)clients[i].connection_id);
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
                    printf("[DBG] Handling AUTH for fd=%d\n", cfd);
                    log_info("Handling AUTH for fd=%d, id=%llu",
                             cfd, (unsigned long long)clients[i].connection_id);
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
                    if (!clients[i].resolving) {
                        printf("[DBG] Starting async REQUEST resolution for fd=%d\n", cfd);
                        log_info("Starting async REQUEST for fd=%d, id=%llu",
                                 cfd, (unsigned long long)clients[i].connection_id);

                        resolve_task_t *task = malloc(sizeof(*task));
                        if (task == NULL) {
                            clients[i].state = STATE_ERROR;
                            break;
                        }
                        task->client_index   = i;
                        task->client_fd      = cfd;
                        task->args           = &args;
                        task->connection_id  = clients[i].connection_id;

                        pthread_t tid;
                        int err = pthread_create(&tid, NULL, resolver_thread, task);
                        if (err != 0) {
                            printf("[ERR] pthread_create failed: %s\n", strerror(err));
                            log_error("pthread_create failed: %s", strerror(err));
                            free(task);
                            clients[i].state = STATE_ERROR;
                            break;
                        }
                        pthread_detach(tid);
                        clients[i].resolving = 1;
                        clients[i].state     = STATE_CONNECTING;
                    }
                    break;

                case STATE_CONNECTING:
                    /* Esperamos a que el thread escriba en el pipe. */
                    break;

                case STATE_RELAYING:
                    if (clients[i].remote_fd != -1 && r_client) {
                        relay_data(cfd, clients[i].remote_fd, i);
                    }
                    if (clients[i].remote_fd != -1 && r_remote) {
                        relay_data(clients[i].remote_fd, cfd, i);
                    }
                    break;

                case STATE_ERROR:
                    printf("[ERR] Client in error state (fd=%d), closing.\n", cfd);
                    log_error("Closing client due to error (fd=%d, id=%llu)",
                              cfd, (unsigned long long)clients[i].connection_id);
                    remove_client(i, &master_set);
                    break;

                case STATE_DONE:
                    printf("[INF] Client session done (fd=%d), removing.\n", cfd);
                    remove_client(i, &master_set);
                    break;

                default:
                    break;
            }
        }
    }

    printf("[INF] Server exiting...\n");
    close(server_fd);
    close(mgmt_fd);
    if (dns_pipe_fds[0] != -1) close(dns_pipe_fds[0]);
    if (dns_pipe_fds[1] != -1) close(dns_pipe_fds[1]);
    mgmt_cleanup_shared_memory();
    return 0;
}
