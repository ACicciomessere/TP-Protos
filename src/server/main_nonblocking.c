/**
 * main_nonblocking.c - High-Performance SOCKS5 Proxy Server
 *
 * This server can handle 500+ concurrent connections using a hybrid approach:
 * - Non-blocking selector for accepting new connections
 * - Thread pool for handling SOCKS5 protocol (reuses existing handlers)
 * - Efficient memory management and connection tracking
 * 
 * Features:
 * - Non-blocking connection acceptance
 * - Username/password authentication (RFC1929)
 * - IPv4/IPv6/FQDN support
 * - Concurrent SOCKS5 and management connections
 * - Real-time statistics and monitoring
 */

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

// Constants
#define MAX_THREAD_POOL_SIZE 500
#define MAX_PENDING_CONNECTIONS 1024
#define STATISTICS_UPDATE_INTERVAL 10

// Server state
static bool done = false;
static struct socks5args server_args;
static fd_selector main_selector = NULL;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread pool management
static pthread_t thread_pool[MAX_THREAD_POOL_SIZE];
static bool thread_pool_active[MAX_THREAD_POOL_SIZE];
static pthread_mutex_t thread_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

// Statistics - thread safe
static struct {
    size_t total_connections;
    size_t current_connections;
    size_t peak_connections;
    size_t bytes_transferred;
    size_t failed_connections;
    time_t start_time;
} server_stats = {0};

/**
 * Connection data passed to worker threads
 */
struct connection_data {
    int client_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct socks5args* args;
    time_t connection_start;
    int thread_slot;
};

// Forward declarations
static void* handle_socks5_connection_thread(void* arg);
static void* handle_management_connection_thread(void* arg);
static void update_statistics(int delta_connections, ssize_t bytes_delta);
static void print_server_statistics(void);
static int find_available_thread_slot(void);
static void cleanup_finished_threads(void);

// Signal handlers
static void sigterm_handler(int signal) {
    printf("\n[INF] Received signal %d, shutting down gracefully...\n", signal);
    done = true;
}

static void sigchld_handler(int sig) {
    // Clean up any zombie processes
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void sigusr1_handler(int sig) {
    // Print statistics on SIGUSR1
    print_server_statistics();
}

// Thread-safe statistics update
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
    
    printf("\n=== SOCKS5 Server Statistics ===\n");
    printf("Uptime: %ld seconds\n", uptime);
    printf("Total connections: %zu\n", server_stats.total_connections);
    printf("Current connections: %zu\n", server_stats.current_connections);
    printf("Peak concurrent connections: %zu\n", server_stats.peak_connections);
    printf("Bytes transferred: %zu\n", server_stats.bytes_transferred);
    printf("Failed connections: %zu\n", server_stats.failed_connections);
    if (uptime > 0) {
        printf("Connections per second: %.2f\n", (double)server_stats.total_connections / uptime);
    }
    printf("================================\n\n");
    
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
        fprintf(stderr, "[ERR] Invalid address format: %s\n", address);
        return -1;
    }
    
    server_fd = socket(family, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[ERR] socket()");
        return -1;
    }
    
    // Set socket options
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("[ERR] setsockopt(SO_REUSEADDR)");
        close(server_fd);
        return -1;
    }
    
    // Bind to address based on family
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
            perror("[ERR] bind()");
            close(server_fd);
            return -1;
        }
    } else {
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        
        int ipv6only = 0;
        if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) < 0) {
            perror("[ERR] setsockopt(IPV6_V6ONLY)");
            close(server_fd);
            return -1;
        }
        
        if (strcmp(address, "::") == 0) {
            addr6.sin6_addr = in6addr_any;
        } else {
            inet_pton(AF_INET6, address, &addr6.sin6_addr);
        }
        
        if (bind(server_fd, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
            perror("[ERR] bind()");
            close(server_fd);
            return -1;
        }
    }
    
    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("[ERR] listen()");
        close(server_fd);
        return -1;
    }
    
    // Set non-blocking for selector
    if (selector_set_nonblocking(server_fd) < 0) {
        perror("[ERR] Setting server socket non-blocking");
        close(server_fd);
        return -1;
    }
    
    return server_fd;
}

// Thread management functions
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
    return -1; // No available slots
}

static void release_thread_slot(int slot) {
    pthread_mutex_lock(&thread_pool_mutex);
    thread_pool_active[slot] = false;
    pthread_mutex_unlock(&thread_pool_mutex);
}

static void cleanup_finished_threads(void) {
    // Since we're using detached threads, we don't need to explicitly clean them up
    // The thread slots are managed by the thread functions themselves
    // This function is kept for future enhancements
}

// SOCKS5 connection handler thread
static void* handle_socks5_connection_thread(void* arg) {
    struct connection_data* conn_data = (struct connection_data*)arg;
    int client_fd = conn_data->client_fd;
    struct socks5args* args = conn_data->args;
    int thread_slot = conn_data->thread_slot;
    
    // Set thread to detached so it cleans up automatically
    pthread_detach(pthread_self());
    
    // Log connection
    char addr_str[INET6_ADDRSTRLEN];
    if (conn_data->client_addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)&conn_data->client_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, addr_str, sizeof(addr_str));
        printf("[INF] SOCKS5 connection from %s:%d [Thread %d]\n", 
               addr_str, ntohs(addr_in->sin_port), thread_slot);
    } else {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)&conn_data->client_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, addr_str, sizeof(addr_str));
        printf("[INF] SOCKS5 connection from [%s]:%d [Thread %d]\n", 
               addr_str, ntohs(addr_in6->sin6_port), thread_slot);
    }
    
    // Handle the SOCKS5 protocol using existing handler
    int result = handleClient(client_fd, args);
    
    time_t connection_duration = time(NULL) - conn_data->connection_start;
    
    if (result == 0) {
        printf("[INF] SOCKS5 connection completed successfully (duration: %ld seconds)\n", connection_duration);
    } else {
        printf("[INF] SOCKS5 connection failed (duration: %ld seconds)\n", connection_duration);
        pthread_mutex_lock(&stats_mutex);
        server_stats.failed_connections++;
        pthread_mutex_unlock(&stats_mutex);
    }
    
    // Update statistics
    update_statistics(-1, 0); // Decrement connection count
    
    // Release thread slot
    release_thread_slot(thread_slot);
    
    // Cleanup
    free(conn_data);
    
    return NULL;
}

// Management connection handler thread  
static void* handle_management_connection_thread(void* arg) {
    struct connection_data* conn_data = (struct connection_data*)arg;
    int client_fd = conn_data->client_fd;
    
    pthread_detach(pthread_self());
    
    printf("[INF] Management connection established\n");
    
    // Simple management protocol - echo commands for now
    char buffer[1024];
    ssize_t bytes_read;
    
    while ((bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        
        // Simple command processing
        if (strncmp(buffer, "STATS", 5) == 0) {
            // Send statistics
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
            // Echo unknown commands
            send(client_fd, buffer, bytes_read, 0);
        }
    }
    
    close(client_fd);
    printf("[INF] Management connection closed\n");
    
    free(conn_data);
    return NULL;
}

// Connection accept handlers for selector
static void socks5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("[ERR] accept() on SOCKS5 socket");
        }
        return;
    }
    
    // Find available thread slot
    int thread_slot = find_available_thread_slot();
    if (thread_slot == -1) {
        printf("[WARN] No available thread slots, rejecting connection\n");
        close(client_fd);
        pthread_mutex_lock(&stats_mutex);
        server_stats.failed_connections++;
        pthread_mutex_unlock(&stats_mutex);
        return;
    }
    
    // Create connection data
    struct connection_data* conn_data = malloc(sizeof(struct connection_data));
    if (!conn_data) {
        printf("[ERR] Failed to allocate connection data\n");
        close(client_fd);
        release_thread_slot(thread_slot);
        return;
    }
    
    conn_data->client_fd = client_fd;
    conn_data->client_addr = client_addr;
    conn_data->client_addr_len = client_addr_len;
    conn_data->args = &server_args;
    conn_data->connection_start = time(NULL);
    conn_data->thread_slot = thread_slot;
    
    // Create thread to handle connection
    if (pthread_create(&thread_pool[thread_slot], NULL, handle_socks5_connection_thread, conn_data) != 0) {
        perror("[ERR] pthread_create() for SOCKS5 connection");
        close(client_fd);
        free(conn_data);
        release_thread_slot(thread_slot);
        return;
    }
    
    // Update statistics
    update_statistics(1, 0); // Increment connection count
}

static void mgmt_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    int client_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            perror("[ERR] accept() on management socket");
        }
        return;
    }
    
    // Create connection data
    struct connection_data* conn_data = malloc(sizeof(struct connection_data));
    if (!conn_data) {
        printf("[ERR] Failed to allocate management connection data\n");
        close(client_fd);
        return;
    }
    
    conn_data->client_fd = client_fd;
    conn_data->client_addr = client_addr;
    conn_data->client_addr_len = client_addr_len;
    conn_data->args = &server_args;
    conn_data->connection_start = time(NULL);
    
    // Create detached thread for management connection
    pthread_t mgmt_thread;
    if (pthread_create(&mgmt_thread, NULL, handle_management_connection_thread, conn_data) != 0) {
        perror("[ERR] pthread_create() for management connection");
        close(client_fd);
        free(conn_data);
        return;
    }
}

// Handler definitions for selector
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
    // Disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    // Parse arguments
    parse_args(argc, argv, &server_args);
    
    // Initialize statistics
    server_stats.start_time = time(NULL);
    
    // Display configuration
    printf("[INF] High-Performance SOCKS5 Proxy Server\n");
    printf("[INF] SOCKS5 address: %s:%d\n", server_args.socks_addr, server_args.socks_port);
    printf("[INF] Management address: %s:%d\n", server_args.mng_addr, server_args.mng_port);
    printf("[INF] Max concurrent connections: %d\n", MAX_THREAD_POOL_SIZE);
    
    // Count configured users
    int user_count = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (server_args.users[i].name && server_args.users[i].pass) {
            user_count++;
        }
    }
    printf("[INF] Configured users: %d\n", user_count);
    
    if (user_count > 0) {
        printf("[INF] Username/password authentication enabled\n");
    } else {
        printf("[INF] No authentication required\n");
    }
    
    // Initialize shared memory for statistics
    if (mgmt_init_shared_memory() < 0) {
        fprintf(stderr, "[ERR] Failed to initialize shared memory\n");
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);
    signal(SIGCHLD, sigchld_handler);
    signal(SIGUSR1, sigusr1_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Initialize thread pool
    memset(thread_pool_active, false, sizeof(thread_pool_active));
    
    // Create server sockets
    int socks5_fd = create_server_socket(server_args.socks_addr, server_args.socks_port);
    if (socks5_fd < 0) {
        fprintf(stderr, "[ERR] Failed to create SOCKS5 server socket\n");
        mgmt_cleanup_shared_memory();
        return 1;
    }
    
    int mgmt_fd = create_server_socket(server_args.mng_addr, server_args.mng_port);
    if (mgmt_fd < 0) {
        fprintf(stderr, "[ERR] Failed to create management server socket\n");
        close(socks5_fd);
        mgmt_cleanup_shared_memory();
        return 1;
    }
    
    // Initialize selector
    const struct selector_init_config config = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 1,
            .tv_nsec = 0,
        },
    };
    
    if (selector_initialize(&config) != SELECTOR_SUCCESS) {
        fprintf(stderr, "[ERR] Failed to initialize selector\n");
        close(socks5_fd);
        close(mgmt_fd);
        mgmt_cleanup_shared_memory();
        return 1;
    }
    
    main_selector = selector_create(1024);
    if (!main_selector) {
        fprintf(stderr, "[ERR] Failed to create selector\n");
        close(socks5_fd);
        close(mgmt_fd);
        mgmt_cleanup_shared_memory();
        return 1;
    }
    
    // Register server sockets
    if (selector_register(main_selector, socks5_fd, &socks5_passive_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        fprintf(stderr, "[ERR] Failed to register SOCKS5 server socket\n");
        goto cleanup;
    }
    
    if (selector_register(main_selector, mgmt_fd, &mgmt_passive_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        fprintf(stderr, "[ERR] Failed to register management server socket\n");
        goto cleanup;
    }
    
    printf("[INF] Server ready - accepting connections\n");
    printf("[INF] Send SIGUSR1 (kill -USR1 %d) for statistics\n", getpid());
    
    // Statistics reporting timer
    time_t last_stats_time = time(NULL);
    
    // Main event loop
    while (!done) {
        selector_status status = selector_select(main_selector);
        if (status != SELECTOR_SUCCESS) {
            if (status == SELECTOR_IO && errno == EINTR) {
                continue;  // Interrupted by signal
            }
            fprintf(stderr, "[ERR] Selector error: %s\n", selector_strerror(status));
            break;
        }
        
        // Periodic cleanup and statistics
        time_t current_time = time(NULL);
        if (current_time - last_stats_time >= STATISTICS_UPDATE_INTERVAL) {
            cleanup_finished_threads();
            last_stats_time = current_time;
            
            // Update shared memory statistics
            pthread_mutex_lock(&stats_mutex);
            shared_data_t* shared = mgmt_get_shared_data();
            if (shared) {
                shared->stats.total_connections = server_stats.total_connections;
                shared->stats.current_connections = server_stats.current_connections;
                shared->stats.total_bytes_transferred = server_stats.bytes_transferred;
            }
            pthread_mutex_unlock(&stats_mutex);
        }
    }
    
    printf("[INF] Shutting down gracefully...\n");
    
    // Print final statistics
    print_server_statistics();
    
    // Wait for active connections to finish (with timeout)
    printf("[INF] Waiting for active connections to finish...\n");
    int wait_count = 0;
    while (server_stats.current_connections > 0 && wait_count < 30) {
        sleep(1);
        wait_count++;
        cleanup_finished_threads();
    }
    
    if (server_stats.current_connections > 0) {
        printf("[WARN] Forcing shutdown with %zu active connections\n", server_stats.current_connections);
    }

cleanup:
    selector_destroy(main_selector);
    selector_cleanup();
    close(socks5_fd);
    close(mgmt_fd);
    mgmt_cleanup_shared_memory();
    
    return 0;
}