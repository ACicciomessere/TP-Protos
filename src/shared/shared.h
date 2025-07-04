#ifndef __shared_h_
#define __shared_h_

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define MGMT_PORT 8080
#define MGMT_HOST "127.0.0.1"
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_USERS 10
#define MAX_MESSAGE_LEN 1024

// Comandos del protocolo de gestión
typedef enum {
    CMD_ADD_USER,
    CMD_DEL_USER,
    CMD_LIST_USERS,
    CMD_STATS
} mgmt_command_t;

// Estructura para almacenar un usuario
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    int active;
} user_t;

// Estructura para estadísticas
typedef struct {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t total_bytes_transferred;
    uint64_t current_bytes_transferred;
    int current_users;
} stats_t;

// Estructura para datos compartidos entre procesos
typedef struct {
    user_t users[MAX_USERS];
    stats_t stats;
    int user_count;
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

// Funciones para comunicación cliente-servidor
int mgmt_connect_to_server(void);
int mgmt_send_command(int sock, mgmt_command_t cmd, const char* username, const char* password);
int mgmt_receive_response(int sock, mgmt_response_t* response);
void mgmt_close_connection(int sock);

// Funciones para el servidor
int mgmt_server_start(int port);
int mgmt_handle_client(int client_sock);

// Funciones para memoria compartida
int mgmt_init_shared_memory(void);
void mgmt_cleanup_shared_memory(void);
shared_data_t* mgmt_get_shared_data(void);

// Funciones para actualizar estadísticas
void mgmt_update_stats(uint64_t bytes_transferred, int connection_change);

// Funciones utilitarias
void sayHello(void);

#endif
