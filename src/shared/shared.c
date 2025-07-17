#include "shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include "../logger.h"

// Pointer to shared data
static shared_data_t* g_shared_data = NULL;

void sayHello(void) {
    log_info("Hello!");
}

// Initialize shared memory
int mgmt_init_shared_memory(void) {
    // Create shared memory using mmap
    g_shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE, 
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    if (g_shared_data == MAP_FAILED) {
        log_fatal("Error creating shared memory: %s", strerror(errno));
        return -1;
    }
    
    // Initialize the structure
    memset(g_shared_data, 0, sizeof(shared_data_t));
    
    // Initialize server start time
    g_shared_data->stats.server_start_time = time(NULL);
    
    // Configure mutexes to be shared between processes
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    
    pthread_mutex_init(&g_shared_data->users_mutex, &attr);
    pthread_mutex_init(&g_shared_data->stats_mutex, &attr);
    
    pthread_mutexattr_destroy(&attr);
    
    log_info("Shared memory initialized");
    return 0;
}

// Cleanup shared memory
void mgmt_cleanup_shared_memory(void) {
    if (g_shared_data != NULL) {
        pthread_mutex_destroy(&g_shared_data->users_mutex);
        pthread_mutex_destroy(&g_shared_data->stats_mutex);
        munmap(g_shared_data, sizeof(shared_data_t));
        g_shared_data = NULL;
        log_info("Shared memory cleaned up");
    }
}

// Get pointer to shared data
shared_data_t* mgmt_get_shared_data(void) {
    return g_shared_data;
}

// Function to find a user
static int find_user(const char* username) {
    for (int i = 0; i < g_shared_data->user_count; i++) {
        if (g_shared_data->users[i].active && strcmp(g_shared_data->users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

// Function to add a user
static int add_user(const char* username, const char* password) {
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    // Check if the user already exists
    if (find_user(username) != -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return -1; // User already exists
    }
    
    // Find a free slot
    int slot = -1;
    for (int i = 0; i < MAX_USERS; i++) {
        if (!g_shared_data->users[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return -2; // No space available
    }
    
    // Add user
    strncpy(g_shared_data->users[slot].username, username, MAX_USERNAME_LEN - 1);
    strncpy(g_shared_data->users[slot].password, password, MAX_PASSWORD_LEN - 1);
    g_shared_data->users[slot].username[MAX_USERNAME_LEN - 1] = '\0';
    g_shared_data->users[slot].password[MAX_PASSWORD_LEN - 1] = '\0';
    g_shared_data->users[slot].active = 1;
    
    if (slot >= g_shared_data->user_count) {
        g_shared_data->user_count = slot + 1;
    }
    
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    return 0;
}

// Function to delete a user
static int delete_user(const char* username) {
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    int index = find_user(username);
    if (index == -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return -1; // User not found
    }
    
    g_shared_data->users[index].active = 0;
    memset(&g_shared_data->users[index], 0, sizeof(user_t));
    
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    return 0;
}

// Function to get a list of users
static int get_users(user_t* user_list, int max_users) {
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    int count = 0;
    for (int i = 0; i < g_shared_data->user_count && count < max_users; i++) {
        if (g_shared_data->users[i].active) {
            memcpy(&user_list[count], &g_shared_data->users[i], sizeof(user_t));
            count++;
        }
    }
    
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    return count;
}

// Function to get stats
static void get_stats(stats_t* stats) {
    pthread_mutex_lock(&g_shared_data->stats_mutex);
    memcpy(stats, &g_shared_data->stats, sizeof(stats_t));
    pthread_mutex_unlock(&g_shared_data->stats_mutex);
}

// Function to update global stats
void mgmt_update_stats(uint64_t bytes_transferred, int connection_change) {
    if (g_shared_data == NULL) return;
    
    pthread_mutex_lock(&g_shared_data->stats_mutex);
    
    if (connection_change > 0) {
        g_shared_data->stats.total_connections++;
        g_shared_data->stats.current_connections++;
        
        // Update peak concurrent connections
        if (g_shared_data->stats.current_connections > g_shared_data->stats.peak_concurrent_connections) {
            g_shared_data->stats.peak_concurrent_connections = g_shared_data->stats.current_connections;
        }
    } else if (connection_change < 0) {
        g_shared_data->stats.current_connections--;
    }
    
    g_shared_data->stats.total_bytes_transferred += bytes_transferred;
    g_shared_data->stats.current_bytes_transferred += bytes_transferred;
    // Log the update of global metrics
    log_debug("Global stats updated: bytes=%llu conn_change=%d total_conn=%llu active_conn=%llu total_bytes=%llu", 
               (unsigned long long)bytes_transferred, connection_change, 
               (unsigned long long)g_shared_data->stats.total_connections, 
               (unsigned long long)g_shared_data->stats.current_connections, 
               (unsigned long long)g_shared_data->stats.total_bytes_transferred);
    
    pthread_mutex_unlock(&g_shared_data->stats_mutex);
}

// Function to update per-user stats
void mgmt_update_user_stats(const char* username, uint64_t bytes_transferred, int connection_change) {
    if (g_shared_data == NULL || username == NULL) return;
    
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    // Find the user
    int user_index = find_user(username);
    if (user_index == -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return; // User not found
    }
    
    user_stats_t* user_stats = &g_shared_data->users[user_index].stats;
    time_t current_time = time(NULL);
    
    if (connection_change > 0) {
        user_stats->total_connections++;
        user_stats->current_connections++;
        user_stats->last_connection_time = current_time;
        
        // If it's the first connection, set the first connection time
        if (user_stats->first_connection_time == 0) {
            user_stats->first_connection_time = current_time;
        }
    } else if (connection_change < 0) {
        user_stats->current_connections--;
        
        // Calculate connection time and add it to the total
        if (user_stats->last_connection_time > 0) {
            uint64_t connection_duration = current_time - user_stats->last_connection_time;
            user_stats->total_connection_time += connection_duration;
        }
    }
    
    user_stats->total_bytes_transferred += bytes_transferred;
    user_stats->current_bytes_transferred += bytes_transferred;
    // Log the update of per-user metrics
    log_debug("User stats for '%s' updated: bytes=%llu conn_change=%d total_conn=%llu active_conn=%llu total_bytes=%llu", 
               username, (unsigned long long)bytes_transferred, connection_change, 
               (unsigned long long)user_stats->total_connections, 
               (unsigned long long)user_stats->current_connections, 
               (unsigned long long)user_stats->total_bytes_transferred);
    
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    
    // Also update global stats
    mgmt_update_stats(bytes_transferred, connection_change);
}

// Handle management client with optimized protocol
int mgmt_handle_client(int client_sock) {
    if (g_shared_data == NULL) {
        log_error("Shared memory not initialized");
        return -1;
    }
    
    mgmt_message_t msg;
    
    // Receive message
    ssize_t bytes_received = recv(client_sock, &msg, sizeof(msg), 0);
    if (bytes_received <= 0) {
        if (bytes_received < 0) {
            log_warn("recv from mgmt client failed: %s", strerror(errno));
        } else {
            log_info("Management client disconnected");
        }
        return -1;
    }
    
    // Process command with optimized structures
    switch (msg.command) {
        case CMD_ADD_USER:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                
                int result = add_user(msg.username, msg.password);
                if (result == 0) {
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message), "User %s added successfully", msg.username);
                } else if (result == -1) {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: User %s already exists", msg.username);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: No space for more users");
                }
                
                return mgmt_send_simple_response(client_sock, &response);
            }
            
        case CMD_DEL_USER:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                
                int result = delete_user(msg.username);
                if (result == 0) {
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message), "User %s deleted successfully", msg.username);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: User %s not found", msg.username);
                }
                
                return mgmt_send_simple_response(client_sock, &response);
            }
            
        case CMD_LIST_USERS:
            {
                mgmt_users_response_t response;
                memset(&response, 0, sizeof(response));
                
                response.user_count = get_users(response.users, MAX_USERS);
                response.success = 1;
                snprintf(response.message, sizeof(response.message), "User list obtained (%d users)", response.user_count);
                
                return mgmt_send_users_response(client_sock, &response);
            }
            
        case CMD_STATS:
            {
                mgmt_stats_response_t response;
                memset(&response, 0, sizeof(response));
                
                get_stats(&response.stats);
                // Only send the number of configured users, not specific data
                pthread_mutex_lock(&g_shared_data->users_mutex);
                int active_users = 0;
                for (int i = 0; i < g_shared_data->user_count; i++) {
                    if (g_shared_data->users[i].active) {
                        active_users++;
                    }
                }
                pthread_mutex_unlock(&g_shared_data->users_mutex);
                
                response.user_count = active_users;
                response.success = 1;
                snprintf(response.message, sizeof(response.message), "General stats obtained (%d configured users)", active_users);
                
                return mgmt_send_stats_response(client_sock, &response);
            }
            
        default:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                
                response.success = 0;
                snprintf(response.message, sizeof(response.message), "Command not recognized");
                
                return mgmt_send_simple_response(client_sock, &response);
            }
    }
}

// Connect to management server
int mgmt_connect_to_server(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(MGMT_PORT);
    if (inet_pton(AF_INET, MGMT_HOST, &server_addr.sin_addr) <= 0) {
        log_error("inet_pton() failed for %s", MGMT_HOST);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("connect() to mgmt server failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

// Send command to server
int mgmt_send_command(int sock, mgmt_command_t cmd, const char* username, const char* password) {
    mgmt_message_t msg;
    
    memset(&msg, 0, sizeof(msg));
    msg.command = cmd;
    
    if (username) {
        strncpy(msg.username, username, MAX_USERNAME_LEN - 1);
        msg.username[MAX_USERNAME_LEN - 1] = '\0';
    }
    
    if (password) {
        strncpy(msg.password, password, MAX_PASSWORD_LEN - 1);
        msg.password[MAX_PASSWORD_LEN - 1] = '\0';
    }
    
    ssize_t bytes_sent = send(sock, &msg, sizeof(msg), 0);
    if (bytes_sent < 0) {
        log_error("send() to mgmt server failed: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

// Receive response from server
int mgmt_receive_response(int sock, mgmt_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = recv(sock, response, sizeof(mgmt_response_t), 0);
    if (n < 0) {
        log_error("recv() from mgmt server failed: %s", strerror(errno));
    }
    return (n > 0) ? 0 : -1;
}

// Close connection
void mgmt_close_connection(int sock) {
    if (sock >= 0) {
        close(sock);
    }
}

// Optimized functions for specific command communication

// Receive optimized stats response
int mgmt_receive_stats_response(int sock, mgmt_stats_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = recv(sock, response, sizeof(mgmt_stats_response_t), 0);
    if (n < 0) {
        log_error("recv(stats) from mgmt server failed: %s", strerror(errno));
    }
    return (n > 0) ? 0 : -1;
}

// Receive optimized users response
int mgmt_receive_users_response(int sock, mgmt_users_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = recv(sock, response, sizeof(mgmt_users_response_t), 0);
    if (n < 0) {
        log_error("recv(users) from mgmt server failed: %s", strerror(errno));
    }
    return (n > 0) ? 0 : -1;
}

// Receive optimized simple response
int mgmt_receive_simple_response(int sock, mgmt_simple_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = recv(sock, response, sizeof(mgmt_simple_response_t), 0);
    if (n < 0) {
        log_error("recv(simple) from mgmt server failed: %s", strerror(errno));
    }
    return (n > 0) ? 0 : -1;
}

// Send optimized stats response
int mgmt_send_stats_response(int sock, mgmt_stats_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = send(sock, response, sizeof(mgmt_stats_response_t), 0);
    if (n < 0) {
        log_error("send(stats) to mgmt client failed: %s", strerror(errno));
    }
    return (n == sizeof(mgmt_stats_response_t)) ? 0 : -1;
}

// Send optimized users response
int mgmt_send_users_response(int sock, mgmt_users_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = send(sock, response, sizeof(mgmt_users_response_t), 0);
    if (n < 0) {
        log_error("send(users) to mgmt client failed: %s", strerror(errno));
    }
    return (n == sizeof(mgmt_users_response_t)) ? 0 : -1;
}

// Send optimized simple response
int mgmt_send_simple_response(int sock, mgmt_simple_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t n = send(sock, response, sizeof(mgmt_simple_response_t), 0);
    if (n < 0) {
        log_error("send(simple) to mgmt client failed: %s", strerror(errno));
    }
    return (n == sizeof(mgmt_simple_response_t)) ? 0 : -1;
}

// Start management server
int mgmt_server_start(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        log_fatal("mgmt socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    int reuse = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        log_fatal("mgmt setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_fatal("mgmt bind() failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        log_fatal("mgmt listen() failed: %s", strerror(errno));
        close(server_sock);
        return -1;
    }

    log_info("Management server started on port %d", port);
    return server_sock;
}
