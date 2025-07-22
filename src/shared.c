#include "shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <fcntl.h> // Para fcntl
#include <sys/socket.h> // Para fcntl

// Helpers para enviar/recibir todo el payload
static int send_all(int sock, const void* buffer, size_t length) {
    const uint8_t* ptr = (const uint8_t*)buffer;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t n = send(sock, ptr, remaining, 0);
        if (n <= 0) {
            return -1;
        }
        ptr += n;
        remaining -= n;
    }
    return 0;
}

static int recv_all(int sock, void* buffer, size_t length) {
    uint8_t* ptr = (uint8_t*)buffer;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t n = recv(sock, ptr, remaining, 0);
        if (n <= 0) {
            return -1;
        }
        ptr += n;
        remaining -= n;
    }
    return 0;
}

// Configuración dinámica del servidor
static int g_connection_timeout_ms = 10000;   // Timeout por defecto (ms)
static int g_buffer_size = 4096;              // Tamaño de buffer por defecto (bytes)
static int g_max_clients = 1024;              // Máximo de clientes por defecto
static bool g_dissectors_enabled = true;      // Disectores habilitados

// Puntero a datos compartidos
static shared_data_t* g_shared_data = NULL;

// Persistencia de usuarios en un archivo sencillo
#define USERS_PERSIST_FILE "auth.db"

// Forward declaration para usar antes de su definición real
static int add_user(const char* username, const char* password);

void sayHello(void) {
    printf("Hello!\n");
}

// Guarda los usuarios activos al disco
static void save_users_to_file(void) {
    if (g_shared_data == NULL) return;
    FILE* f = fopen(USERS_PERSIST_FILE, "w");
    if (!f) { perror("Opening users file for write"); return; }

    pthread_mutex_lock(&g_shared_data->users_mutex);
    for (int i = 0; i < g_shared_data->user_count; i++) {
        if (g_shared_data->users[i].active) {
            fprintf(f, "%s:%s\n", g_shared_data->users[i].username,
                             g_shared_data->users[i].password);
        }
    }
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    fclose(f);
}

// Carga los usuarios desde disco (si el archivo existe)
static void load_users_from_file(void) {
    if (g_shared_data == NULL) return;
    FILE* f = fopen(USERS_PERSIST_FILE, "r");
    if (!f) return; // No hay archivo, no es un error

    char line[MAX_USERNAME_LEN + MAX_PASSWORD_LEN + 2]; // username:pass\n\0
    while (fgets(line, sizeof(line), f)) {
        // Remover salto de linea
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char* sep = strchr(line, ':');
        if (!sep) continue;
        *sep = '\0';
        const char* username = line;
        const char* password = sep + 1;

        pthread_mutex_lock(&g_shared_data->users_mutex);
        if (g_shared_data->user_count < MAX_USERS) {
            int slot = g_shared_data->user_count;
            strncpy(g_shared_data->users[slot].username, username, MAX_USERNAME_LEN - 1);
            strncpy(g_shared_data->users[slot].password, password, MAX_PASSWORD_LEN - 1);
            g_shared_data->users[slot].username[MAX_USERNAME_LEN - 1] = '\0';
            g_shared_data->users[slot].password[MAX_PASSWORD_LEN - 1] = '\0';
            g_shared_data->users[slot].active = 1;
            g_shared_data->user_count = slot + 1;
        }
        pthread_mutex_unlock(&g_shared_data->users_mutex);
    }
    fclose(f);
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
    
    // Inicializar tiempo de inicio del servidor
    g_shared_data->stats.server_start_time = time(NULL);
    
    // Configurar los mutex como compartidos entre procesos
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    
    pthread_mutex_init(&g_shared_data->users_mutex, &attr);
    pthread_mutex_init(&g_shared_data->stats_mutex, &attr);
    
    g_shared_data->connection_id_counter = 0;
    
    pthread_mutexattr_destroy(&attr);

    // Cargar usuarios persistidos, si existen
    load_users_from_file();

    // if (g_shared_data->user_count == 0) {
    //     // Aseguramos que exista el usuario por defecto "admin:admin"
    //     add_user("admin", "admin");
    // }

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

    // Persistir cambios
    save_users_to_file();
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

    // Persistir cambios
    save_users_to_file();
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

// Función para actualizar estadísticas globales
void mgmt_update_stats(uint64_t bytes_transferred, int connection_change) {
    if (g_shared_data == NULL) return;
    
    pthread_mutex_lock(&g_shared_data->stats_mutex);
    
    if (connection_change > 0) {
        g_shared_data->stats.total_connections++;
        g_shared_data->stats.current_connections++;
        
        // Actualizar pico de conexiones concurrentes
        if (g_shared_data->stats.current_connections > g_shared_data->stats.peak_concurrent_connections) {
            g_shared_data->stats.peak_concurrent_connections = g_shared_data->stats.current_connections;
        }
    } else if (connection_change < 0) {
        g_shared_data->stats.current_connections--;
    }
    
    g_shared_data->stats.total_bytes_transferred += bytes_transferred;
    g_shared_data->stats.current_bytes_transferred += bytes_transferred;
    
    pthread_mutex_unlock(&g_shared_data->stats_mutex);
}

// Función para actualizar estadísticas por usuario
void mgmt_update_user_stats(const char* username, uint64_t bytes_transferred, int connection_change) {
    if (g_shared_data == NULL || username == NULL) return;
    
    pthread_mutex_lock(&g_shared_data->users_mutex);
    
    // Buscar el usuario
    int user_index = find_user(username);
    if (user_index == -1) {
        pthread_mutex_unlock(&g_shared_data->users_mutex);
        return; // Usuario no encontrado
    }
    
    user_stats_t* user_stats = &g_shared_data->users[user_index].stats;
    time_t current_time = time(NULL);
    
    if (connection_change > 0) {
        user_stats->total_connections++;
        user_stats->current_connections++;
        user_stats->last_connection_time = current_time;
        
        // Si es la primera conexión, establecer tiempo de primera conexión
        if (user_stats->first_connection_time == 0) {
            user_stats->first_connection_time = current_time;
        }
    } else if (connection_change < 0) {
        user_stats->current_connections--;
        
        // Calcular tiempo de conexión y agregarlo al total
        if (user_stats->last_connection_time > 0) {
            uint64_t connection_duration = current_time - user_stats->last_connection_time;
            user_stats->total_connection_time += connection_duration;
        }
    }
    
    user_stats->total_bytes_transferred += bytes_transferred;
    user_stats->current_bytes_transferred += bytes_transferred;
    
    pthread_mutex_unlock(&g_shared_data->users_mutex);
    
    // También actualizar estadísticas globales
    mgmt_update_stats(bytes_transferred, connection_change);
}

uint64_t mgmt_get_next_connection_id(void) {
    if (g_shared_data == NULL) return 0;
    // GCC/Clang built-in para incremento atómico
    return __sync_add_and_fetch(&g_shared_data->connection_id_counter, 1);
}

// Manejar cliente de gestión con protocolo optimizado
int mgmt_handle_client(int client_sock) {
    if (g_shared_data == NULL) {
        printf("[ERR] Shared memory not initialized\n");
        return -1;
    }
    
    mgmt_message_t msg;
    
    // Recibir mensaje completo
    if (recv_all(client_sock, &msg, sizeof(msg)) < 0) {
        return -1;
    }
    
    // Procesar comando con estructuras optimizadas
    switch (msg.command) {
        case CMD_ADD_USER:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                
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
                
                return mgmt_send_simple_response(client_sock, &response);
            }
            
        case CMD_DEL_USER:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                
                int result = delete_user(msg.username);
                if (result == 0) {
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message), "Usuario %s eliminado exitosamente", msg.username);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message), "Error: Usuario %s no encontrado", msg.username);
                }
                
                return mgmt_send_simple_response(client_sock, &response);
            }
            
        case CMD_LIST_USERS:
            {
                mgmt_users_response_t response;
                memset(&response, 0, sizeof(response));
                
                response.user_count = get_users(response.users, MAX_USERS);
                response.success = 1;
                snprintf(response.message, sizeof(response.message), "Lista de usuarios obtenida (%d usuarios)", response.user_count);
                
                return mgmt_send_users_response(client_sock, &response);
            }
            
        case CMD_STATS:
            {
                mgmt_stats_response_t response;
                memset(&response, 0, sizeof(response));
                
                get_stats(&response.stats);
                // Solo enviar el número de usuarios configurados, no los datos específicos
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
                snprintf(response.message, sizeof(response.message), "Estadísticas generales obtenidas (%d usuarios configurados)", active_users);
                
                return mgmt_send_stats_response(client_sock, &response);
            }

        case CMD_SET_TIMEOUT:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));

                int ms = atoi(msg.username);  // El valor llega como string en username
                if (ms > 0) {
                    g_connection_timeout_ms = ms;
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message),
                             "Timeout de conexión configurado en %d ms", ms);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message),
                             "Valor de timeout inválido");
                }

                return mgmt_send_simple_response(client_sock, &response);
            }

        case CMD_SET_BUFFER:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));

                int bytes = atoi(msg.username);
                if (bytes > 0) {
                    g_buffer_size = bytes;
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message),
                             "Tamaño de buffer configurado en %d bytes", bytes);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message),
                             "Valor de buffer inválido");
                }

                return mgmt_send_simple_response(client_sock, &response);
            }

        case CMD_SET_MAX_CLIENTS:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));

                int num = atoi(msg.username);
                if (num > 0) {
                    g_max_clients = num;
                    response.success = 1;
                    snprintf(response.message, sizeof(response.message),
                             "Máximo de clientes configurado en %d", num);
                } else {
                    response.success = 0;
                    snprintf(response.message, sizeof(response.message),
                             "Valor de máximo de clientes inválido");
                }

                return mgmt_send_simple_response(client_sock, &response);
            }

        case CMD_ENABLE_DISSECTORS:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                g_dissectors_enabled = true;
                response.success = 1;
                snprintf(response.message, sizeof(response.message),
                         "Disectores habilitados");
                return mgmt_send_simple_response(client_sock, &response);
            }

        case CMD_DISABLE_DISSECTORS:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                g_dissectors_enabled = false;
                response.success = 1;
                snprintf(response.message, sizeof(response.message),
                         "Disectores deshabilitados");
                return mgmt_send_simple_response(client_sock, &response);
            }

        case CMD_RELOAD_CONFIG:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                // En una implementación real, aquí se volvería a cargar la configuración
                // desde un archivo. Por ahora, se envía éxito.
                response.success = 1;
                snprintf(response.message, sizeof(response.message),
                         "Configuración recargada exitosamente");
                return mgmt_send_simple_response(client_sock, &response);
            }

        case CMD_GET_CONFIG:
            {
                mgmt_config_response_t response;
                memset(&response, 0, sizeof(response));
                response.success = 1;
                response.timeout_ms = g_connection_timeout_ms;
                response.buffer_size = g_buffer_size;
                response.max_clients = g_max_clients;
                response.dissectors_enabled = g_dissectors_enabled ? 1 : 0;
                snprintf(response.message, sizeof(response.message),
                         "Configuración actual obtenida");
                return mgmt_send_config_response(client_sock, &response);
            }
        
        default:
            {
                mgmt_simple_response_t response;
                memset(&response, 0, sizeof(response));
                
                response.success = 0;
                snprintf(response.message, sizeof(response.message), "Comando no reconocido");
                
                return mgmt_send_simple_response(client_sock, &response);
            }
    }
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
    
    if (send_all(sock, &msg, sizeof(msg)) < 0) {
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

// Funciones optimizadas para comunicación específica por comando

// Recibir respuesta de estadísticas optimizada
int mgmt_receive_stats_response(int sock, mgmt_stats_response_t* response) {
    if (!response) return -1;
    return recv_all(sock, response, sizeof(*response));
}

// Recibir respuesta de usuarios optimizada
int mgmt_receive_users_response(int sock, mgmt_users_response_t* response) {
    if (!response) return -1;
    return recv_all(sock, response, sizeof(*response));
}

// Recibir respuesta simple optimizada
int mgmt_receive_simple_response(int sock, mgmt_simple_response_t* response) {
    if (!response) return -1;
    return recv_all(sock, response, sizeof(*response));
}

// Enviar respuesta de estadísticas optimizada
int mgmt_send_stats_response(int sock, mgmt_stats_response_t* response) {
    if (!response) return -1;
    return send_all(sock, response, sizeof(*response));
}

// Enviar respuesta de usuarios optimizada
int mgmt_send_users_response(int sock, mgmt_users_response_t* response) {
    if (!response) return -1;
    return send_all(sock, response, sizeof(*response));
}

// Enviar respuesta simple optimizada
int mgmt_send_simple_response(int sock, mgmt_simple_response_t* response) {
    if (!response) return -1;
    return send_all(sock, response, sizeof(*response));
}

// -------- Config response helpers --------
int mgmt_send_config_response(int sock, mgmt_config_response_t* response) {
    return send_all(sock, response, sizeof(*response));
}

int mgmt_receive_config_response(int sock, mgmt_config_response_t* response) {
    if (!response) return -1;
    return recv_all(sock, response, sizeof(*response));
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


#include <pthread.h>

// Hilo que acepta conexiones entrantes del servidor de gestión
void* mgmt_accept_loop(void* arg) {
    int server_sock = *((int*)arg);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock >= 0) {
            // Asegurar modo bloqueante para operaciones sencillas de recv/send
            int flags = fcntl(client_sock, F_GETFL, 0);
            if (flags != -1) {
                fcntl(client_sock, F_SETFL, flags & ~O_NONBLOCK);
            }
            mgmt_handle_client(client_sock);
            close(client_sock);
        }
    }
    return NULL;
}
