// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#include "socks5.h"
#include "util.h"
#include "../shared/shared.h"
#include "../args.h"

#define MAX_PENDING_CONNECTION_REQUESTS 5
#define TEST_SOCKS5_REPLY 1 

// Note: SIGCHLD handler removed since we no longer use fork()

// Manejar señal SIGTERM y SIGINT para limpieza
void cleanup_handler(int sig);

// Función para manejar conexiones de gestión
void handle_management_connection(int client_sock) {
    printf("[INF] Handling management connection\n");
    
    if (mgmt_handle_client(client_sock) < 0) {
        printf("[ERR] Error handling management client\n");
    }
    
    close(client_sock);
    printf("[INF] Management connection closed\n");
}

// Función para manejar conexiones SOCKS5
void handle_socks5_connection(int client_sock, struct socks5args* args) {
    printf("[INF] Handling SOCKS5 connection\n");


    // Disabled test mode to enable proper SOCKS5 functionality
    #if 0
        printf("[TEST] Enviando respuesta SOCKS5 de error (REPLY_CONNECTION_REFUSED)\n");
        send_socks5_reply(client_sock, REPLY_CONNECTION_REFUSED);
        close(client_sock);
        return;
    #endif

    
    // Actualizar estadísticas - nueva conexión
    mgmt_update_stats(0, 1);
    
    int result = handleClient(client_sock, args);
    if (result < 0) {
        printf("[ERR] Error handling SOCKS5 client\n");
    }
    
    // Actualizar estadísticas - conexión cerrada
    mgmt_update_stats(0, -1);
    
    close(client_sock);
    printf("[INF] SOCKS5 connection closed\n");
}

// Crear socket servidor
int create_server_socket(int port) {
    int serverSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0) {
        perror("[ERR] socket()");
        return -1;
    }

    // Configurar para reutilizar la dirección
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[ERR] setsockopt()");
        close(serverSocket);
        return -1;
    }

    struct sockaddr_in6 srcSocket;
    memset((char*)&srcSocket, 0, sizeof(srcSocket));
    srcSocket.sin6_family = AF_INET6;
    srcSocket.sin6_port = htons(port);
    memcpy(&srcSocket.sin6_addr, &in6addr_any, sizeof(in6addr_any));

    if (bind(serverSocket, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        perror("[ERR] bind()");
        close(serverSocket);
        return -1;
    }

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        perror("[ERR] listen()");
        close(serverSocket);
        return -1;
    }

    return serverSocket;
}

// Manejar señal SIGTERM y SIGINT para limpieza
void cleanup_handler(int sig) {
    printf("[INF] Received signal %d, cleaning up...\n", sig);
    mgmt_cleanup_shared_memory();
    exit(0);
}

int main(int argc, char* argv[]) {
    // Disable buffering on stdout and stderr
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Parse command line arguments
    struct socks5args args;
    parse_args(argc, argv, &args);

    // Show configuration
    printf("[INF] SOCKS5 server configuration:\n");
    printf("  SOCKS5 address: %s:%d\n", args.socks_addr, args.socks_port);
    printf("  Management address: %s:%d\n", args.mng_addr, args.mng_port);
    printf("  Disectors enabled: %s\n", args.disectors_enabled ? "yes" : "no");
    
    // Show configured users
    int userCount = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name && args.users[i].pass) {
            userCount++;
        }
    }
    printf("  Configured users: %d\n", userCount);
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name && args.users[i].pass) {
            printf("    - %s\n", args.users[i].name);
        }
    }
    
    if (userCount > 0) {
        printf("[INF] Username/password authentication will be required\n");
    } else {
        printf("[INF] No authentication will be required\n");
    }

    // Inicializar memoria compartida
    if (mgmt_init_shared_memory() < 0) {
        fprintf(stderr, "[ERR] Failed to initialize shared memory\n");
        exit(1);
    }

    // Note: SIGCHLD handler removed since we no longer use fork()

    // Configurar manejador de señales para limpieza
    signal(SIGTERM, cleanup_handler);
    signal(SIGINT, cleanup_handler);

    // Crear socket para SOCKS5
    int socks5Socket = create_server_socket(args.socks_port);
    if (socks5Socket < 0) {
        mgmt_cleanup_shared_memory();
        exit(1);
    }

    // Crear socket para gestión
    int mgmtSocket = create_server_socket(args.mng_port);
    if (mgmtSocket < 0) {
        close(socks5Socket);
        mgmt_cleanup_shared_memory();
        exit(1);
    }

    // Mostrar información de binding
    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    
    if (getsockname(socks5Socket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] SOCKS5 server listening on %s\n", addrBuffer);
    }
    
    if (getsockname(mgmtSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        printf("[INF] Management server listening on %s\n", addrBuffer);
    }

    // Usar select() para manejar múltiples sockets
    fd_set master_set, read_set;
    int max_sd;
    
    FD_ZERO(&master_set);
    FD_SET(socks5Socket, &master_set);
    FD_SET(mgmtSocket, &master_set);
    max_sd = (socks5Socket > mgmtSocket) ? socks5Socket : mgmtSocket;

    printf("[INF] Server ready, waiting for connections...\n");

    while (1) {
        read_set = master_set;
        
        int select_result = select(max_sd + 1, &read_set, NULL, NULL, NULL);
        if (select_result < 0) {
            if (errno == EINTR) {
                // La señal SIGCHLD interrumpió select(), continuar
                continue;
            } else {
                perror("[ERR] select()");
                break;
            }
        }

        // Verificar socket SOCKS5
        if (FD_ISSET(socks5Socket, &read_set)) {
            struct sockaddr_storage clientAddress;
            socklen_t clientAddressLen = sizeof(clientAddress);
            int clientSocket = accept(socks5Socket, (struct sockaddr*)&clientAddress, &clientAddressLen);
            
            if (clientSocket < 0) {
                perror("[ERR] accept() on SOCKS5 socket");
                continue;
            }

            char addrBuffer[128];
            printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
            printf("[INF] New SOCKS5 connection from %s\n", addrBuffer);

            // Handle SOCKS5 connection directly in main thread (no fork)
            handle_socks5_connection(clientSocket, &args);
        }

        // Verificar socket de gestión
        if (FD_ISSET(mgmtSocket, &read_set)) {
            struct sockaddr_storage clientAddress;
            socklen_t clientAddressLen = sizeof(clientAddress);
            int clientSocket = accept(mgmtSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
            
            if (clientSocket < 0) {
                perror("[ERR] accept() on management socket");
                continue;
            }

            char addrBuffer[128];
            printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
            printf("[INF] New management connection from %s\n", addrBuffer);

            // Handle management connection directly in main thread (no fork)
            handle_management_connection(clientSocket);
        }
    }

    close(socks5Socket);
    close(mgmtSocket);
    mgmt_cleanup_shared_memory();
    return 0;
}
