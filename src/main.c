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
#define MAX_PENDING_CONNECTION_REQUESTS 128

/* Límite defensivo para buffers configurables por management.
 * Evita que un SET_BUFFER malicioso dispare mallocs gigantes.
 */
#define MIN_BUFFER_CAP 256
#define MAX_BUFFER_CAP (1024 * 1024) /* 1 MiB */

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

    /* --- handshake buffer (no bloqueante) --- */
    unsigned char hs_buf[512];
    size_t        hs_len;

    /* request ya parseado (Camino A) */
    char     req_addr[256];
    uint16_t req_port;
    int      req_ready;

    /* --- relay buffers (writes parciales/backpressure) --- */
    unsigned char *c2r_buf;
    size_t        c2r_len;
    size_t        c2r_sent;

    unsigned char *r2c_buf;
    size_t        r2c_len;
    size_t        r2c_sent;

    size_t        buf_cap; /* capacidad actual de c2r_buf/r2c_buf */

    int closed;
    int resolving;
} client_t;

client_t clients[MAX_CLIENTS];

/* Pipe para comunicar threads de resolución/CONNECT con el loop principal. */
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

    char dest_addr[256];
    uint16_t dest_port;
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

static void reset_relay_buffers(client_t *cl) {
    cl->c2r_len = cl->c2r_sent = 0;
    cl->r2c_len = cl->r2c_sent = 0;
}

static size_t clamp_buffer_cap(int requested) {
    if (requested < MIN_BUFFER_CAP) return MIN_BUFFER_CAP;
    if (requested > (int)MAX_BUFFER_CAP) return MAX_BUFFER_CAP;
    return (size_t)requested;
}

/* Asegura que el cliente tenga buffers asignados con la capacidad deseada.
 * Solo redimensiona si NO hay datos pendientes en los buffers.
 */
static int ensure_relay_buffers(client_t *cl, size_t desired_cap) {
    if (cl->buf_cap == desired_cap && cl->c2r_buf != NULL && cl->r2c_buf != NULL) return 0;

    /* No re-dimensionar en caliente si hay data pendiente */
    if (cl->c2r_len != 0 || cl->r2c_len != 0) return 0;

    unsigned char *new_c2r = (unsigned char *)malloc(desired_cap);
    unsigned char *new_r2c = (unsigned char *)malloc(desired_cap);
    if (new_c2r == NULL || new_r2c == NULL) {
        free(new_c2r);
        free(new_r2c);
        return -1;
    }

    free(cl->c2r_buf);
    free(cl->r2c_buf);
    cl->c2r_buf = new_c2r;
    cl->r2c_buf = new_r2c;
    cl->buf_cap = desired_cap;
    reset_relay_buffers(cl);
    return 0;
}

static void reset_handshake_buffer(client_t *cl) {
    cl->hs_len = 0;
    cl->req_addr[0] = '\0';
    cl->req_port = 0;
    cl->req_ready = 0;
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
    free(clients[i].c2r_buf);
    free(clients[i].r2c_buf);
    clients[i].c2r_buf = NULL;
    clients[i].r2c_buf = NULL;
    clients[i].buf_cap = 0;
    reset_handshake_buffer(&clients[i]);
    reset_relay_buffers(&clients[i]);
}

/* Thread que hace connect + reply (REQUEST ya parseado en main) */
static void *resolver_thread(void *arg) {
    resolve_task_t *task = (resolve_task_t *)arg;
    dns_result_t res;
    res.client_index = task->client_index;

    int remote_fd = socks5_connect_and_reply(task->client_fd,
                                             task->dest_addr,
                                             task->dest_port,
                                             task->connection_id);

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

int count_active_clients(void) {
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].client_fd != -1) {
            count++;
        }
    }
    return count;
}

/* ---------- Relay con buffers ---------- */

static int try_flush(int fd, unsigned char *buf, size_t *len, size_t *sent) {
    if (*len == 0) return 0;
    while (*sent < *len) {
        ssize_t n = send(fd, buf + *sent, *len - *sent, 0);
        if (n > 0) {
            *sent += (size_t)n;
            mgmt_update_stats(n, 0);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return -1;
    }
    *len = 0;
    *sent = 0;
    return 0;
}

static int try_read_into(int from_fd, unsigned char *buf, size_t cap, size_t *len, size_t *sent) {
    (void)sent;
    if (*len != 0) return 0;

    ssize_t n = recv(from_fd, buf, cap, 0);
    if (n > 0) {
        *len = (size_t)n;
        *sent = 0;
        return 0;
    }
    if (n == 0) return 1;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
    return -1;
}

/* ------------------------------------------------------------------ */
/* --------- Handshake NO-bloqueante (GREETING/AUTH/REQUEST) ---------- */

static void hs_consume(client_t *cl, size_t n) {
    if (n >= cl->hs_len) {
        cl->hs_len = 0;
        return;
    }
    memmove(cl->hs_buf, cl->hs_buf + n, cl->hs_len - n);
    cl->hs_len -= n;
}

/* return:  1 = leí bytes, 0 = no había, -2 = EOF, -1 = error */
static int hs_recv_into(client_t *cl) {
    if (cl->hs_len >= sizeof(cl->hs_buf)) return 0;

    ssize_t n = recv(cl->client_fd,
                     cl->hs_buf + cl->hs_len,
                     sizeof(cl->hs_buf) - cl->hs_len,
                     0);

    if (n > 0) { cl->hs_len += (size_t)n; return 1; }
    if (n == 0) return -2;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
    return -1;
}

/* return: 1 avanzó, 0 falta data, <0 error */
static int handle_greeting_nb(client_t *cl, struct socks5args *args) {
    (void)args;

    if (cl->hs_len < 2) return 0;
    uint8_t ver = cl->hs_buf[0];
    uint8_t nmethods = cl->hs_buf[1];

    if (ver != SOCKS_VERSION || nmethods == 0) return -1;
    if (cl->hs_len < (size_t)(2 + nmethods)) return 0;

    uint8_t method = -1;

    for(int i = 0; i < nmethods; i++) {
        if (cl->hs_buf[2 + i] == SOCKS5_AUTH_USERPASS) {
            method = SOCKS5_AUTH_USERPASS;
            break;
        }
    }
    
    hs_consume(cl, 2 + nmethods);

    uint8_t resp[2] = { SOCKS_VERSION, method };
    ssize_t s = send(cl->client_fd, resp, 2, 0);
    if (s != 2 || method != SOCKS5_AUTH_USERPASS) return -1;

    cl->state = STATE_AUTH;
    return 1;
}

/* return: 1 avanzó, 0 falta data, <0 error */
static int handle_auth_nb(client_t *cl, struct socks5args *args) {
    if (cl->hs_len < 2) return 0;

    uint8_t ver = cl->hs_buf[0];
    uint8_t ulen = cl->hs_buf[1];
    if (ver != 0x01 || ulen == 0) return -1;

    if (cl->hs_len < (size_t)(2 + ulen + 1)) return 0;
    uint8_t plen = cl->hs_buf[2 + ulen];
    if (plen == 0) return -1;

    size_t total = 2 + (size_t)ulen + 1 + (size_t)plen;
    if (total > sizeof(cl->hs_buf)) return -1;
    if (cl->hs_len < total) return 0;

    char user[256], pass[256];
    memcpy(user, cl->hs_buf + 2, ulen);
    user[ulen] = '\0';
    memcpy(pass, cl->hs_buf + 2 + ulen + 1, plen);
    pass[plen] = '\0';

    int ok = validateUser(user, pass, args);

    uint8_t resp[2] = { 0x01, ok ? 0x00 : 0x01 };
    ssize_t s = send(cl->client_fd, resp, 2, 0);
    if (s != 2) return -1;

    hs_consume(cl, total);

    if (ok) cl->state = STATE_REQUEST;
    else    cl->state = STATE_ERROR;

    return 1;
}

/*
 * Parse REQUEST desde hs_buf (Camino A).
 * return:  1 = request listo (cl->req_ready=1), 0 = falta data, <0 error (y manda reply)
 */
static int handle_request_nb(client_t *cl) {
    if (cl->req_ready) return 1;

    if (cl->hs_len < 4) return 0;

    uint8_t ver  = cl->hs_buf[0];
    uint8_t cmd  = cl->hs_buf[1];
    uint8_t rsv  = cl->hs_buf[2];
    uint8_t atyp = cl->hs_buf[3];
    (void)rsv;

    if (ver != SOCKS_VERSION) {
        (void)send_socks5_reply(cl->client_fd, REPLY_GENERAL_SOCKS_SERVER_FAILURE);
        return -1;
    }
    if (cmd != 0x01) { /* solo CONNECT */
        (void)send_socks5_reply(cl->client_fd, REPLY_COMMAND_NOT_SUPPORTED);
        return -1;
    }

    size_t need = 0;

    if (atyp == 0x01) {            /* IPv4 */
        need = 4 + 4 + 2;          /* hdr + addr4 + port */
        if (cl->hs_len < need) return 0;

        struct in_addr a4;
        memcpy(&a4, cl->hs_buf + 4, 4);

        uint16_t p;
        memcpy(&p, cl->hs_buf + 8, 2);
        cl->req_port = ntohs(p);

        if (inet_ntop(AF_INET, &a4, cl->req_addr, sizeof(cl->req_addr)) == NULL) {
            (void)send_socks5_reply(cl->client_fd, REPLY_GENERAL_SOCKS_SERVER_FAILURE);
            return -1;
        }

        hs_consume(cl, need);

    } else if (atyp == 0x03) {     /* DOMAIN */
        if (cl->hs_len < 5) return 0; /* hdr + len */
        uint8_t len = cl->hs_buf[4];
        if (len == 0 || len > 255) {
            (void)send_socks5_reply(cl->client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
            return -1;
        }

        need = 4 + 1 + (size_t)len + 2;
        if (need > sizeof(cl->hs_buf)) {
            (void)send_socks5_reply(cl->client_fd, REPLY_GENERAL_SOCKS_SERVER_FAILURE);
            return -1;
        }
        if (cl->hs_len < need) return 0;

        if (len >= sizeof(cl->req_addr)) {
            (void)send_socks5_reply(cl->client_fd, REPLY_GENERAL_SOCKS_SERVER_FAILURE);
            return -1;
        }

        memcpy(cl->req_addr, cl->hs_buf + 5, len);
        cl->req_addr[len] = '\0';

        uint16_t p;
        memcpy(&p, cl->hs_buf + 5 + len, 2);
        cl->req_port = ntohs(p);

        hs_consume(cl, need);

    } else if (atyp == 0x04) {     /* IPv6 */
        need = 4 + 16 + 2;
        if (cl->hs_len < need) return 0;

        struct in6_addr a6;
        memcpy(&a6, cl->hs_buf + 4, 16);

        uint16_t p;
        memcpy(&p, cl->hs_buf + 20, 2);
        cl->req_port = ntohs(p);

        if (inet_ntop(AF_INET6, &a6, cl->req_addr, sizeof(cl->req_addr)) == NULL) {
            (void)send_socks5_reply(cl->client_fd, REPLY_GENERAL_SOCKS_SERVER_FAILURE);
            return -1;
        }

        hs_consume(cl, need);

    } else {
        (void)send_socks5_reply(cl->client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
        return -1;
    }

    cl->req_ready = 1;
    return 1;
}

/* ------------------------------------------------------------------ */

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
        clients[i].c2r_buf      = NULL;
        clients[i].r2c_buf      = NULL;
        clients[i].buf_cap      = 0;
        reset_handshake_buffer(&clients[i]);
        reset_relay_buffers(&clients[i]);
    }

    fd_set master_set;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    FD_SET(dns_pipe_fds[0], &master_set);

    int fdmax = server_fd;
    if (dns_pipe_fds[0] > fdmax) fdmax = dns_pipe_fds[0];

    signal(SIGINT, cleanup_handler);

    while (1) {
        fd_set read_set = master_set;
        fd_set write_set;
        FD_ZERO(&write_set);

        /* Aplicar buffer dinámico a conexiones existentes (sin data pendiente) */
        size_t desired_cap = clamp_buffer_cap(mgmt_get_buffer_size());
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].client_fd == -1) continue;
            if (clients[i].state != STATE_RELAYING) continue;
            (void)ensure_relay_buffers(&clients[i], desired_cap);
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].client_fd == -1) continue;
            if (clients[i].state != STATE_RELAYING) continue;
            if (clients[i].remote_fd == -1) continue;

            if (clients[i].c2r_len != 0) FD_SET(clients[i].remote_fd, &write_set);
            if (clients[i].r2c_len != 0) FD_SET(clients[i].client_fd, &write_set);
        }

        /* Timeout configurable: evita el "select() sin timeout" que marcó la cátedra. */
        int timeout_ms = mgmt_get_timeout_ms();
        if (timeout_ms <= 0) timeout_ms = 1000;
        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (select(fdmax + 1, &read_set, &write_set, NULL, &tv) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        /* 1) Resultados de CONNECT desde threads */
        if (FD_ISSET(dns_pipe_fds[0], &read_set)) {
            dns_result_t res;
            while (1) {
                ssize_t n = read(dns_pipe_fds[0], &res, sizeof(res));
                if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                if (n != sizeof(res)) break;

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

                    /* Asegurar buffers para el relay usando el tamaño actual configurado */
                    if (ensure_relay_buffers(cl, clamp_buffer_cap(mgmt_get_buffer_size())) < 0) {
                        /* Si no hay memoria, cerramos la conexión remota y marcamos error */
                        FD_CLR(cl->remote_fd, &master_set);
                        close(cl->remote_fd);
                        cl->remote_fd = -1;
                        cl->state = STATE_ERROR;
                        break;
                    }
                    reset_relay_buffers(cl);
                    cl->state = STATE_RELAYING;

                    printf("[INF] CONNECT done for fd=%d, remote_fd=%d, switching to RELAYING\n",
                           cl->client_fd, cl->remote_fd);
                } else {
                    cl->state = STATE_ERROR;
                    printf("[ERR] CONNECT failed for fd=%d, setting STATE_ERROR\n", cl->client_fd);
                }
            }
        }

        /* 2) Nuevas conexiones */
        if (FD_ISSET(server_fd, &read_set)) {
            struct sockaddr_storage client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
            if (client_fd >= 0) {
                set_nonblocking(client_fd);

                /* select() usa fd_set: si se supera FD_SETSIZE, se rompe.
                 * Rechazamos defensivamente.
                 */
                if (client_fd >= FD_SETSIZE) {
                    log_error("FD %d >= FD_SETSIZE (%d), rejecting", client_fd, FD_SETSIZE);
                    close(client_fd);
                    continue;
                }

                int active = count_active_clients();
                int max_allowed = mgmt_get_max_clients();
                if (max_allowed <= 0 || max_allowed > MAX_CLIENTS) max_allowed = MAX_CLIENTS;

                if (active >= max_allowed) {
                    printf("[ERR] Max clients reached (%d), rejecting fd=%d\n", max_allowed, client_fd);
                    log_error("Max clients reached (%d), rejecting fd=%d", max_allowed, client_fd);
                    close(client_fd);
                } else {
                    int i = find_available_client_slot();
                    if (i >= 0) {
                        clients[i].client_fd       = client_fd;
                        clients[i].connection_id   = mgmt_get_next_connection_id();
                        clients[i].remote_fd       = -1;
                        clients[i].state           = STATE_GREETING;
                        clients[i].addr            = client_addr;
                        clients[i].addr_len        = addrlen;
                        clients[i].closed          = 0;
                        clients[i].resolving       = 0;
                        reset_handshake_buffer(&clients[i]);
                        reset_relay_buffers(&clients[i]);

                        /* Buffer configurable (impacta transferencia real) */
                        size_t cap = clamp_buffer_cap(mgmt_get_buffer_size());
                        if (ensure_relay_buffers(&clients[i], cap) < 0) {
                            log_error("Failed to allocate relay buffers (cap=%zu)", cap);
                            close(client_fd);
                            clients[i].client_fd = -1;
                            clients[i].state = STATE_DONE;
                            break;
                        }

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

        /* 3) Manejo de clientes */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int cfd = clients[i].client_fd;
            if (cfd == -1) continue;

            int r_client = FD_ISSET(cfd, &read_set);
            int r_remote = (clients[i].remote_fd != -1 && FD_ISSET(clients[i].remote_fd, &read_set));

            int w_client = FD_ISSET(cfd, &write_set);
            int w_remote = (clients[i].remote_fd != -1 && FD_ISSET(clients[i].remote_fd, &write_set));

            switch (clients[i].state) {
                case STATE_GREETING: {
                    if (r_client) {
                        int rr = hs_recv_into(&clients[i]);
                        if (rr == -2) { clients[i].state = STATE_DONE; break; }
                        if (rr < 0)   { clients[i].state = STATE_ERROR; break; }
                    }
                    int step = handle_greeting_nb(&clients[i], &args);
                    if (step < 0) clients[i].state = STATE_ERROR;
                } break;

                case STATE_AUTH: {
                    if (r_client) {
                        int rr = hs_recv_into(&clients[i]);
                        if (rr == -2) { clients[i].state = STATE_DONE; break; }
                        if (rr < 0)   { clients[i].state = STATE_ERROR; break; }
                    }
                    int step = handle_auth_nb(&clients[i], &args);
                    if (step < 0) clients[i].state = STATE_ERROR;
                } break;

                case STATE_REQUEST: {
                    /* OJO: puede ya haber request en hs_buf sin nuevo readable */
                    if (r_client) {
                        int rr = hs_recv_into(&clients[i]);
                        if (rr == -2) { clients[i].state = STATE_DONE; break; }
                        if (rr < 0)   { clients[i].state = STATE_ERROR; break; }
                    }

                    int pr = handle_request_nb(&clients[i]);
                    if (pr < 0) { clients[i].state = STATE_ERROR; break; }
                    if (pr == 0) break; /* falta data */

                    if (!clients[i].resolving) {
                        resolve_task_t *task = malloc(sizeof(*task));
                        if (task == NULL) {
                            clients[i].state = STATE_ERROR;
                            break;
                        }

                        task->client_index   = i;
                        task->client_fd      = cfd;
                        task->args           = &args;
                        task->connection_id  = clients[i].connection_id;

                        strncpy(task->dest_addr, clients[i].req_addr, sizeof(task->dest_addr) - 1);
                        task->dest_addr[sizeof(task->dest_addr) - 1] = '\0';
                        task->dest_port = clients[i].req_port;

                        pthread_t tid;
                        int err = pthread_create(&tid, NULL, resolver_thread, task);
                        if (err != 0) {
                            log_error("pthread_create failed: %s", strerror(err));
                            free(task);
                            clients[i].state = STATE_ERROR;
                            break;
                        }
                        pthread_detach(tid);

                        clients[i].resolving = 1;
                        clients[i].state     = STATE_CONNECTING;
                    }
                } break;

                case STATE_CONNECTING:
                    /* Esperamos a que el thread escriba en el pipe */
                    break;

                case STATE_RELAYING: {
                    if (clients[i].remote_fd == -1) break;

                    /* En caso de que el relay entre sin buffers (defensivo) */
                    if (clients[i].c2r_buf == NULL || clients[i].r2c_buf == NULL || clients[i].buf_cap == 0) {
                        size_t cap = clamp_buffer_cap(mgmt_get_buffer_size());
                        if (ensure_relay_buffers(&clients[i], cap) < 0) {
                            clients[i].state = STATE_ERROR;
                            break;
                        }
                    }

                    if (w_remote && clients[i].c2r_len != 0) {
                        if (try_flush(clients[i].remote_fd, clients[i].c2r_buf,
                                      &clients[i].c2r_len, &clients[i].c2r_sent) < 0) {
                            clients[i].state = STATE_ERROR;
                            break;
                        }
                    }
                    if (w_client && clients[i].r2c_len != 0) {
                        if (try_flush(cfd, clients[i].r2c_buf,
                                      &clients[i].r2c_len, &clients[i].r2c_sent) < 0) {
                            clients[i].state = STATE_ERROR;
                            break;
                        }
                    }

                    if (r_client) {
                        int rr = try_read_into(cfd, clients[i].c2r_buf, clients[i].buf_cap,
                                               &clients[i].c2r_len, &clients[i].c2r_sent);
                        if (rr == 1) { clients[i].state = STATE_DONE; break; }
                        if (rr < 0)  { clients[i].state = STATE_ERROR; break; }

                        if (clients[i].c2r_len != 0) {
                            if (try_flush(clients[i].remote_fd, clients[i].c2r_buf,
                                          &clients[i].c2r_len, &clients[i].c2r_sent) < 0) {
                                clients[i].state = STATE_ERROR;
                                break;
                            }
                        }
                    }

                    if (r_remote) {
                        int rr = try_read_into(clients[i].remote_fd, clients[i].r2c_buf, clients[i].buf_cap,
                                               &clients[i].r2c_len, &clients[i].r2c_sent);
                        if (rr == 1) { clients[i].state = STATE_DONE; break; }
                        if (rr < 0)  { clients[i].state = STATE_ERROR; break; }

                        if (clients[i].r2c_len != 0) {
                            if (try_flush(cfd, clients[i].r2c_buf,
                                          &clients[i].r2c_len, &clients[i].r2c_sent) < 0) {
                                clients[i].state = STATE_ERROR;
                                break;
                            }
                        }
                    }
                } break;

                case STATE_ERROR:
                    log_error("Closing client due to error (fd=%d, id=%llu)",
                              cfd, (unsigned long long)clients[i].connection_id);
                    remove_client(i, &master_set);
                    break;

                case STATE_DONE:
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
