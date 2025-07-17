#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <time.h>

#include "../selector.h"
#include "../args.h"
#include "../shared/shared.h"
#include "socks5.h"
#include "../logger.h"

#define MAX_THREAD_POOL_SIZE 500
#define MAX_PENDING_CONNECTIONS 1024
#define STATISTICS_UPDATE_INTERVAL 10

static bool done = false;
static struct socks5args server_args;
static fd_selector main_selector = NULL;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t thread_pool[MAX_THREAD_POOL_SIZE];
static bool thread_pool_active[MAX_THREAD_POOL_SIZE];
static pthread_mutex_t thread_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct {
    size_t total_connections;
    size_t current_connections;
    size_t peak_connections;
    size_t bytes_transferred;
    size_t failed_connections;
    time_t start_time;
} server_stats = {0};

struct connection_data {
    int client_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct socks5args* args;
    time_t connection_start;
    int thread_slot;
};

static void* handle_socks5_connection_thread(void* arg);
static void* handle_management_connection_thread(void* arg);
static void update_statistics(int delta_connections, ssize_t bytes_delta);
static void print_server_statistics(void);
static int find_available_thread_slot(void);

static void sigterm_handler(int signal) {
    log_info("Received signal %d, shutting down gracefully...", signal);
    done = true;
}

static void sigchld_handler(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void sigusr1_handler(int sig) {
    print_server_statistics();
}

static void update_statistics(int delta_connections, ssize_t bytes_delta) {
    pthread_mutex_lock(&stats_mutex);
    
    server_stats.current_connections += delta_connections;
    if (server_stats.current_connections > server_stats.peak_connections) {
        server_stats.peak_connections = server_stats.current_connections;
    }
    
    server_stats.bytes_transferred += bytes_delta;
    
    if (delta_connections > 0) {
        server_stats.total_connections++;
    }
    
    pthread_mutex_unlock(&stats_mutex);
}

static void print_server_statistics(void) {
    pthread_mutex_lock(&stats_mutex);
    
    time_t uptime = time(NULL) - server_stats.start_time;
    
    // Use log_info to print statistics, so they go to the log file
    log_info("--- SOCKS5 Server Statistics ---");
    log_info("Uptime: %ld seconds", uptime);
    log_info("Total connections: %zu", server_stats.total_connections);
    log_info("Current connections: %zu", server_stats.current_connections);
    log_info("Peak concurrent connections: %zu", server_stats.peak_connections);
    log_info("Bytes transferred: %zu", server_stats.bytes_transferred);
    log_info("Failed connections: %zu", server_stats.failed_connections);
    if (uptime > 0) {
        log_info("Connections per second: %.2f", (double)server_stats.total_connections / uptime);
    }
    log_info("---------------------------------");
    
    pthread_mutex_unlock(&stats_mutex);
}

// Socket creation helper
static int create_server_socket(const char *address, int port) {
    int server_fd = -1;
    int family = AF_INET;
    
    // Try to determine if it's IPv4 or IPv6
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    
    if (inet_pton(AF_INET, address, &addr4.sin_addr) == 1) {
        family = AF_INET;
    } else if (inet_pton(AF_INET6, address, &addr6.sin6_addr) == 1) {
        family = AF_INET6;
    } else if (strcmp(address, "0.0.0.0") == 0) {
        family = AF_INET;
    } else {
        log_fatal("Invalid address format: %s", address);
        return -1;
    }
    
    server_fd = socket(family, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_fatal("socket(): %s", strerror(errno));
        return -1;
    }
    
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        log_fatal("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        close(server_fd);
        return -1;
    }
    
    if (family == AF_INET) {
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        
        if (strcmp(address, "0.0.0.0") == 0) {
            addr4.sin_addr.s_addr = INADDR_ANY;
        } else {
            inet_pton(AF_INET, address, &addr4.sin_addr);
        }
        
        if (bind(server_fd, (struct sockaddr*)&addr4, sizeof(addr4)) < 0) {
            log_fatal("bind() on %s:%d failed: %s", address, port, strerror(errno));
            close(server_fd);
            return -1;
        }
    } else {
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        
        int ipv6only = 0;
        if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) < 0) {
            log_fatal("setsockopt(IPV6_V6ONLY): %s", strerror(errno));
            close(server_fd);
            return -1;
        }
        
        if (strcmp(address, "::") == 0) {
            addr6.sin6_addr = in6addr_any;
        } else {
            inet_pton(AF_INET6, address, &addr6.sin6_addr);
        }
        
        if (bind(server_fd, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
            log_fatal("bind() on [%s]:%d failed: %s", address, port, strerror(errno));
            close(server_fd);
            return -1;
        }
    }
    
    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0) {
        log_fatal("listen(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }
    
    if (selector_set_nonblocking(server_fd) < 0) {
        log_error("Setting server socket non-blocking failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }
    
    return server_fd;
}

static int find_available_thread_slot(void) {
    pthread_mutex_lock(&thread_pool_mutex);
    
    for (int i = 0; i < MAX_THREAD_POOL_SIZE; i++) {
        if (!thread_pool_active[i]) {
            thread_pool_active[i] = true;
            pthread_mutex_unlock(&thread_pool_mutex);
            return i;
        }
    }
    
    pthread_mutex_unlock(&thread_pool_mutex);
    return -1; 
}

static void release_thread_slot(int slot) {
    pthread_mutex_lock(&thread_pool_mutex);
    thread_pool_active[slot] = false;
    pthread_mutex_unlock(&thread_pool_mutex);
}

static void* handle_socks5_connection_thread(void* arg) {
    struct connection_data* conn_data = (struct connection_data*)arg;
    int client_fd = conn_data->client_fd;
    struct socks5args* args = conn_data->args;
    int thread_slot = conn_data->thread_slot;
    
    pthread_detach(pthread_self());
    
    char addr_str[INET6_ADDRSTRLEN];
    if (conn_data->client_addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)&conn_data->client_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
        log_info("SOCKS5 connection from %s:%d [Thread %d]", 
               addr_str, ntohs(addr_in->sin_port), thread_slot);
    } else {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&conn_data->client_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
        log_info("SOCKS5 connection from [%s]:%d [Thread %d]", 
               addr_str, ntohs(addr_in6->sin6_port), thread_slot);
    }
    
    int result = handleClient(client_fd, args);
    
    time_t connection_duration = time(NULL) - conn_data->connection_start;
    
    if (result == 0) {
        log_info("SOCKS5 connection completed successfully (duration: %ld seconds)", connection_duration);
    } else {
        log_info("SOCKS5 connection failed (duration: %ld seconds)", connection_duration);
        pthread_mutex_lock(&stats_mutex);
        server_stats.failed_connections++;
        pthread_mutex_unlock(&stats_mutex);
    }
    
    update_statistics(-1, 0); 
    
    release_thread_slot(thread_slot);
    
    free(conn_data);
    
    return NULL;
}

static void* handle_management_connection_thread(void* arg) {
    struct connection_data* conn_data = (struct connection_data*)arg;
    int client_fd = conn_data->client_fd;
    
    pthread_detach(pthread_self());
    
    log_info("Management connection established");
    
    char buffer[1024];
    ssize_t bytes_read;
    
    while ((bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        
        if (strncmp(buffer, "STATS", 5) == 0) {
            char stats_response[1024];
            pthread_mutex_lock(&stats_mutex);
            snprintf(stats_response, sizeof(stats_response),
                    "STATS total=%zu current=%zu peak=%zu bytes=%zu failed=%zu\n",
                    server_stats.total_connections,
                    server_stats.current_connections, 
                    server_stats.peak_connections,
                    server_stats.bytes_transferred,
                    server_stats.failed_connections);
            pthread_mutex_unlock(&stats_mutex);
            
            send(client_fd, stats_response, strlen(stats_response), 0);
        } else if (strncmp(buffer, "QUIT", 4) == 0) {
            send(client_fd, "BYE\n", 4, 0);
            break;
        } else {
            send(client_fd, buffer, bytes_read, 0);
        }
    }
    
    close(client_fd);
    log_info("Management connection closed");
    
    free(conn_data);
    return NULL;
}

static void socks5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        log_warn("accept() failed: %s", strerror(errno));
        return;
    }

    if (selector_set_nonblocking(client_fd) < 0) {
        log_warn("selector_set_nonblocking() for client failed: %s", strerror(errno));
        close(client_fd);
        return;
    }

    int slot = find_available_thread_slot();
    if (slot == -1) {
        log_warn("Max thread pool size reached, dropping connection");
        close(client_fd);
        return;
    }
    
    struct connection_data* conn_data = malloc(sizeof(struct connection_data));
    if (conn_data == NULL) {
        log_error("malloc for connection_data failed");
        close(client_fd);
        release_thread_slot(slot);
        return;
    }
    
    memcpy(&conn_data->client_addr, &client_addr, client_addr_len);
    conn_data->client_addr_len = client_addr_len;
    conn_data->client_fd = client_fd;
    conn_data->args = key->data;
    conn_data->connection_start = time(NULL);
    conn_data->thread_slot = slot;
    
    if (pthread_create(&thread_pool[slot], NULL, handle_socks5_connection_thread, conn_data) != 0) {
        log_error("Failed to create thread for new SOCKS5 connection");
        free(conn_data);
        close(client_fd);
        release_thread_slot(slot);
    }
}


static void mgmt_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        log_warn("accept() for management failed: %s", strerror(errno));
        return;
    }
    if (selector_set_nonblocking(client_fd) < 0) {
        log_warn("selector_set_nonblocking() for mgmt client failed: %s", strerror(errno));
        close(client_fd);
        return;
    }

    struct connection_data* conn_data = malloc(sizeof(struct connection_data));
    if (conn_data == NULL) {
        log_error("malloc for management connection_data failed");
        close(client_fd);
        return;
    }
    
    memcpy(&conn_data->client_addr, &client_addr, client_addr_len);
    conn_data->client_addr_len = client_addr_len;
    conn_data->client_fd = client_fd;
    conn_data->args = key->data;
    
    if (pthread_create(&thread_pool[0], NULL, handle_management_connection_thread, conn_data) != 0) {
        log_error("Failed to create thread for new management connection");
        free(conn_data);
        close(client_fd);
    }
}


static const struct fd_handler socks5_passive_handler = {
    .handle_read = socks5_passive_accept,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = NULL,
};

static const struct fd_handler mgmt_passive_handler = {
    .handle_read = mgmt_passive_accept,
    .handle_write = NULL,
    .handle_block = NULL,  
    .handle_close = NULL,
};

int main(int argc, char *argv[]) {
    // Default log level
    log_level current_log_level = LOG_INFO;
    const char *log_file = "socks5.log"; // Default log file

    // We could parse arguments to change log_level, for now it's fixed
    logger_init(current_log_level, log_file);

    parse_args(argc, argv, &server_args);
    server_stats.start_time = time(NULL);

    // Trap signals
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGCHLD, sigchld_handler);
    signal(SIGUSR1, sigusr1_handler);
    
    // Initialize thread pool
    memset(thread_pool_active, 0, sizeof(thread_pool_active));

    int socks5_server_fd = create_server_socket(server_args.socks_addr, server_args.socks_port);
    if (socks5_server_fd < 0) {
        log_fatal("Failed to create SOCKS5 server socket");
        return 1;
    }
    log_info("SOCKS5 server listening on %s:%d", server_args.socks_addr, server_args.socks_port);

    int mgmt_server_fd = create_server_socket(server_args.mng_addr, server_args.mng_port);
    if (mgmt_server_fd < 0) {
        log_fatal("Failed to create management server socket");
        close(socks5_server_fd);
        return 1;
    }
    log_info("Management server listening on %s:%d", server_args.mng_addr, server_args.mng_port);

    const struct selector_init_config config = {
        .signal = SIGALRM,
        .select_timeout = {.tv_sec = 1, .tv_nsec = 0,},
    };
    
    if (selector_initialize(&config) != SELECTOR_SUCCESS) {
        log_fatal("Failed to initialize selector");
        return 1;
    }
    
    main_selector = selector_create(MAX_PENDING_CONNECTIONS);
    if (main_selector == NULL) {
        log_fatal("Failed to create selector");
        return 1;
    }
    
    if (selector_register(main_selector, socks5_server_fd, &socks5_passive_handler, OP_READ, &server_args) != SELECTOR_SUCCESS) {
        log_fatal("Failed to register SOCKS5 server socket with selector");
        return 1;
    }

    if (selector_register(main_selector, mgmt_server_fd, &mgmt_passive_handler, OP_READ, &server_args) != SELECTOR_SUCCESS) {
        log_fatal("Failed to register management server socket with selector");
        return 1;
    }
    
    log_info("Server started successfully. PID: %d", getpid());
    
    while (!done) {
        selector_status selector_status = selector_select(main_selector);
        if (selector_status != SELECTOR_SUCCESS) {
            if (!done) {
                log_error("selector_select() failed: %s", selector_strerror(selector_status));
            }
        }
    }
    
    log_info("Shutting down server...");
    
    // Clean up
    selector_destroy(main_selector);
    selector_cleanup();
    close(socks5_server_fd);
    close(mgmt_server_fd);
    logger_close();

    log_info("Server shut down gracefully.");
    
    return 0;
}
