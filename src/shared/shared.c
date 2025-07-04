#include "shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

// Puntero a datos compartidos
static shared_data_t* g_shared_data = NULL;

void sayHello(void) {
    printf("Hello!\n");
}

// Inicializar memoria compartida
int mgmt_init_shared_memory(void) {
    // Crear memoria compartida usando mmap
    g_shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE, 
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    if (g_shared_data == MAP_FAILED) {
        perror("Error creating shared memory");
        return -1;
    }
    
    // Inicializar la estructura
    memset(g_shared_data, 0, sizeof(shared_data_t));
    
    // Configurar los mutex como compartidos entre procesos
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    
    pthread_mutex_init(&g_shared_data->users_mutex, &attr);
    pthread_mutex_init(&g_shared_data->stats_mutex, &attr);
    
    pthread_mutexattr_destroy(&attr);
    
    printf("[INF] Shared memory initialized\n");
    return 0;
}

// Limpiar memoria compartida
void mgmt_cleanup_shared_memory(void) {
    if (g_shared_data != NULL) {
        pthread_mutex_destroy(&g_shared_data->users_mutex);
        pthread_mutex_destroy(&g_shared_data->stats_mutex);
        munmap(g_shared_data, sizeof(shared_data_t));
        g_shared_data = NULL;
    }
}

// Obtener puntero a datos compartidos
shared_data_t* mgmt_get_shared_data(void) {
    return g_shared_data;
}

// Función para buscar un usuario
static int find_user(const char* username) {
    for (int i = 0; i < g_shared_data->user_count; i++) {
        if (g_shared_data->users[i].active && strcmp(g_shared_data->users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

// Función para agregar un usuario
static int add_user(const char* username, const char* password) {
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    // Verificar si el usuario ya existe
    if (find_user(username) != -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return -1; // Usuario ya existe
    }
    
    // Buscar slot libre
    int slot = -1;
    for (int i = 0; i < MAX_USERS; i++) {
        if (!g_shared_data->users[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return -2; // No hay espacio
    }
    
    // Agregar usuario
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

// Función para eliminar un usuario
static int delete_user(const char* username) {
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    int index = find_user(username);
    if (index == -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return -1; // Usuario no encontrado
    }
    
    g_shared_data->users[index].active = 0;
    memset(&g_shared_data->users[index], 0, sizeof(user_t));
    
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    return 0;
}

// Función para obtener lista de usuarios
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

// Función para obtener estadísticas
static void get_stats(stats_t* stats) {
    pthread_mutex_lock(&g_shared_data->stats_mutex);
    memcpy(stats, &g_shared_data->stats, sizeof(stats_t));
    pthread_mutex_unlock(&g_shared_data->stats_mutex);
}

// Función para actualizar estadísticas
void mgmt_update_stats(uint64_t bytes_transferred, int connection_change) {
    if (g_shared_data == NULL) return;
    
    pthread_mutex_lock(&g_shared_data->stats_mutex);
    
    if (connection_change > 0) {
        g_shared_data->stats.total_connections++;
        g_shared_data->stats.current_connections++;
    } else if (connection_change < 0) {
        g_shared_data->stats.current_connections--;
    }
    
    g_shared_data->stats.total_bytes_transferred += bytes_transferred;
    g_shared_data->stats.current_bytes_transferred += bytes_transferred;
    
    pthread_mutex_unlock(&g_shared_data->stats_mutex);
}

// Manejar cliente de gestión
int mgmt_handle_client(int client_sock) {
    if (g_shared_data == NULL) {
        printf("[ERR] Shared memory not initialized\n");
        return -1;
    }
    
    mgmt_message_t msg;
    mgmt_response_t response;
    
    memset(&response, 0, sizeof(response));
    
    // Recibir mensaje
    ssize_t bytes_received = recv(client_sock, &msg, sizeof(msg), 0);
    if (bytes_received <= 0) {
        return -1;
    }
    
    // Procesar comando
    switch (msg.command) {
        case CMD_ADD_USER:
            {
                int result = add_user(msg.username, msg.password);
                if (result == 0) {
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message), "Usuario %s agregado exitosamente", msg.username);
                } else if (result == -1) {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: El usuario %s ya existe", msg.username);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: No hay espacio para más usuarios");
                }
            }
            break;
            
        case CMD_DEL_USER:
            {
                int result = delete_user(msg.username);
                if (result == 0) {
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message), "Usuario %s eliminado exitosamente", msg.username);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: Usuario %s no encontrado", msg.username);
                }
            }
            break;
            
        case CMD_LIST_USERS:
            {
                response.user_count = get_users(response.users, MAX_USERS);
                response.success = 1;
                snprintf(response.message, sizeof(response.message), "Lista de usuarios obtenida (%d usuarios)", response.user_count);
            }
            break;
            
        case CMD_STATS:
            {
                get_stats(&response.stats);
                response.success = 1;
                snprintf(response.message, sizeof(response.message), "Estadísticas obtenidas");
            }
            break;
            
        default:
            response.success = 0;
            snprintf(response.message, sizeof(response.message), "Comando no reconocido");
            break;
    }
    
    // Enviar respuesta
    ssize_t bytes_sent = send(client_sock, &response, sizeof(response), 0);
    if (bytes_sent <= 0) {
        return -1;
    }
    
    return 0;
}

// Conectar al servidor de gestión
int mgmt_connect_to_server(void) {
    int sock;
    struct sockaddr_in server_addr;
    
    // Crear socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error creating socket");
        return -1;
    }
    
    // Configurar dirección del servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(MGMT_PORT);
    
    if (inet_pton(AF_INET, MGMT_HOST, &server_addr.sin_addr) <= 0) {
        perror("Error converting address");
        close(sock);
        return -1;
    }
    
    // Conectar
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(sock);
        return -1;
    }
    
    return sock;
}

// Enviar comando al servidor
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
        perror("Error sending message");
        return -1;
    }
    
    return 0;
}

// Recibir respuesta del servidor
int mgmt_receive_response(int sock, mgmt_response_t* response) {
    if (!response) {
        return -1;
    }
    
    ssize_t bytes_received = recv(sock, response, sizeof(mgmt_response_t), 0);
    if (bytes_received < 0) {
        perror("Error receiving response");
        return -1;
    }
    
    if (bytes_received == 0) {
        printf("Server closed connection\n");
        return -1;
    }
    
    return 0;
}

// Cerrar conexión
void mgmt_close_connection(int sock) {
    if (sock >= 0) {
        close(sock);
    }
}

// Iniciar servidor de gestión
int mgmt_server_start(int port) {
    int server_sock;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    // Crear socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Error creating management server socket");
        return -1;
    }
    
    // Configurar opciones del socket
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Error setting socket options");
        close(server_sock);
        return -1;
    }
    
    // Configurar dirección del servidor
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // Bind
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding management server socket");
        close(server_sock);
        return -1;
    }
    
    // Listen
    if (listen(server_sock, 5) < 0) {
        perror("Error listening on management server socket");
        close(server_sock);
        return -1;
    }
    
    printf("[INF] Management server listening on port %d\n", port);
    return server_sock;
}