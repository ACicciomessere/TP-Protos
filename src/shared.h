#ifndef __shared_h_
#define __shared_h_

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>

#define MGMT_PORT 8080
#define MGMT_HOST "127.0.0.1"
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_USERS 10
#define MAX_MESSAGE_LEN 1024
#define DEFAULT_BUFFER_SIZE 4096
#define MAX_BUFFER_CAPACITY 65536
#define MIN_BUFFER_SIZE 512

// Comandos del protocolo de gestión
typedef enum {
    CMD_ADD_USER,
    CMD_DEL_USER,
    CMD_LIST_USERS,
    CMD_STATS,
    CMD_SET_TIMEOUT,
    CMD_SET_BUFFER,
    CMD_SET_MAX_CLIENTS,
    CMD_ENABLE_DISSECTORS,
    CMD_DISABLE_DISSECTORS,
    CMD_RELOAD_CONFIG,
    CMD_GET_CONFIG
} mgmt_command_t;

// Estructura para estadísticas por usuario
typedef struct {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t total_bytes_transferred;
    uint64_t current_bytes_transferred;
    time_t last_connection_time;
    time_t first_connection_time;
    uint64_t total_connection_time;  // Tiempo total conectado en segundos
} user_stats_t;

// Estructura para almacenar un usuario
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    int active;
    user_stats_t stats;  // Estadísticas específicas del usuario
} user_t;

// Estructura para estadísticas globales
typedef struct {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t total_bytes_transferred;
    uint64_t current_bytes_transferred;
    int current_users;
    time_t server_start_time;
    uint64_t peak_concurrent_connections;
} stats_t;

// Estructura para datos compartidos entre procesos
typedef struct {
    user_t users[MAX_USERS];
    stats_t stats;
    int user_count;
    uint64_t connection_id_counter;
    pthread_mutex_t users_mutex;
    pthread_mutex_t stats_mutex;
} shared_data_t;

// Estructura para el mensaje de gestión
typedef struct {
    mgmt_command_t command;
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} mgmt_message_t;

// Estructura para la respuesta
typedef struct {
    int success;
    char message[MAX_MESSAGE_LEN];
    stats_t stats;
    user_t users[MAX_USERS];
    int user_count;
} mgmt_response_t;

// Estructuras de respuesta optimizadas por comando
typedef struct {
    int success;
    char message[MAX_MESSAGE_LEN];
    stats_t stats;
    int user_count;
} mgmt_stats_response_t;

typedef struct {
    int success;
    char message[MAX_MESSAGE_LEN];
    user_t users[MAX_USERS];
    int user_count;
} mgmt_users_response_t;

typedef struct {
    int success;
    char message[MAX_MESSAGE_LEN];
} mgmt_simple_response_t;

// Respuesta de configuración actual
typedef struct {
    int success;
    char message[MAX_MESSAGE_LEN];
    int timeout_ms;
    int buffer_size;
    int max_clients;
    int dissectors_enabled; // 1 habilitado, 0 deshabilitado
} mgmt_config_response_t;

// Funciones para comunicación cliente-servidor
int mgmt_connect_to_server(void);
int mgmt_send_command(int sock, mgmt_command_t cmd, const char* username, const char* password);
int mgmt_receive_response(int sock, mgmt_response_t* response);
void mgmt_close_connection(int sock);
void* mgmt_accept_loop(void* arg);

// Funciones optimizadas para comunicación específica por comando
int mgmt_receive_stats_response(int sock, mgmt_stats_response_t* response);
int mgmt_receive_users_response(int sock, mgmt_users_response_t* response);
int mgmt_receive_simple_response(int sock, mgmt_simple_response_t* response);
int mgmt_receive_config_response(int sock, mgmt_config_response_t* response);
int mgmt_send_config_response(int sock, mgmt_config_response_t* response);
int mgmt_send_stats_response(int sock, mgmt_stats_response_t* response);
int mgmt_send_users_response(int sock, mgmt_users_response_t* response);
int mgmt_send_simple_response(int sock, mgmt_simple_response_t* response);
int mgmt_get_buffer_size(void);
bool mgmt_are_dissectors_enabled(void);

// Funciones para el servidor
int mgmt_server_start(int port);
int mgmt_handle_client(int client_sock);

// Funciones para memoria compartida
int mgmt_init_shared_memory(void);
void mgmt_cleanup_shared_memory(void);
shared_data_t* mgmt_get_shared_data(void);

// Funciones para actualizar estadísticas
void mgmt_update_stats(uint64_t bytes_transferred, int connection_change);
void mgmt_update_user_stats(const char* username, uint64_t bytes_transferred, int connection_change);
uint64_t mgmt_get_next_connection_id(void);

// Funciones utilitarias
void sayHello(void);

#endif
