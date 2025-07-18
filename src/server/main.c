// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <fcntl.h>
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
#include "../logger.h"

#define MAX_PENDING_CONNECTION_REQUESTS 5

// Note: SIGCHLD handler removed since we no longer use fork()

// Manejar señal SIGTERM y SIGINT para limpieza
void cleanup_handler(int sig);

// Función para manejar conexiones de gestión
void handle_management_connection(int client_sock) {
    log_info("Handling management connection");
    
    if (mgmt_handle_client(client_sock) < 0) {
        log_error("Error handling management client");
    }
    
    close(client_sock);
    log_info("Management connection closed");
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
        log_error("Error handling SOCKS5 client");
    }
    
    // Actualizar estadísticas - conexión cerrada
    mgmt_update_stats(0, -1);
    
    close(client_sock);
    log_info("SOCKS5 connection closed");
}

// Crear socket servidor
int create_server_socket(int port) {
    int serverSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0) {
        log_fatal("socket(): %s", strerror(errno));
        return -1;
    }

    // Configurar para reutilizar la dirección
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error("setsockopt(): %s", strerror(errno));
        close(serverSocket);
        return -1;
    }

    struct sockaddr_in6 srcSocket;
    memset((char*)&srcSocket, 0, sizeof(srcSocket));
    srcSocket.sin6_family = AF_INET6;
    srcSocket.sin6_port = htons(port);
    memcpy(&srcSocket.sin6_addr, &in6addr_any, sizeof(in6addr_any));

    if (bind(serverSocket, (struct sockaddr*)&srcSocket, sizeof(srcSocket)) != 0) {
        log_fatal("bind(): %s", strerror(errno));
        close(serverSocket);
        return -1;
    }

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) != 0) {
        log_fatal("listen(): %s", strerror(errno));
        close(serverSocket);
        return -1;
    }

    return serverSocket;
}

// Manejar señal SIGTERM y SIGINT para limpieza
void cleanup_handler(int sig) {
    log_info("Received signal %d, cleaning up...", sig);
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

    logger_init(LOG_INFO, "metrics.log");
    atexit(logger_close);

    // Show configuration

    printf("  SOCKS5 address: %s:%d\n", args.socks_addr, args.socks_port);
    printf("  Management address: %s:%d\n", args.mng_addr, args.mng_port);
    printf("  Disectors enabled: %s\n", args.disectors_enabled ? "yes" : "no");
    
    // Show configured users
    int userCount = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name && args.users[i].pass &&
            args.users[i].name[0] != '\0' && args.users[i].pass[0] != '\0') {
            userCount++;
        }
    }
    printf("  Configured users: %d\n", userCount);
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name && args.users[i].pass &&
            args.users[i].name[0] != '\0' && args.users[i].pass[0] != '\0') {
            printf("    - %s\n", args.users[i].name);
        }
    }
    
    if (userCount > 0) {
        log_info("Username/password authentication will be required");
    } else {
        log_info("No authentication will be required");
    }

    // Inicializar memoria compartida
    if (mgmt_init_shared_memory() < 0) {
        log_fatal("Failed to initialize shared memory");
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
        log_info("SOCKS5 server listening on %s", addrBuffer);
    }
    
    if (getsockname(mgmtSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        char addrBuffer[128];
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log_info("Management server listening on %s", addrBuffer);
    }

    // Usar select() para manejar múltiples sockets
    fd_set master_set, read_set;
    int max_sd;
    
    FD_ZERO(&master_set);
    FD_SET(socks5Socket, &master_set);
    FD_SET(mgmtSocket, &master_set);
    max_sd = (socks5Socket > mgmtSocket) ? socks5Socket : mgmtSocket;

    log_info("Server ready, waiting for connections...");

    while (1) {
        read_set = master_set;
        
        int select_result = select(max_sd + 1, &read_set, NULL, NULL, NULL);
        if (select_result < 0) {
            if (errno == EINTR) {
                // La señal SIGCHLD interrumpió select(), continuar
                continue;
            } else {
                log_error("select(): %s", strerror(errno));
                break;
            }
        }

        // Verificar socket SOCKS5
        if (FD_ISSET(socks5Socket, &read_set)) {
            struct sockaddr_storage clientAddress;
            socklen_t clientAddressLen = sizeof(clientAddress);
            int clientSocket = accept(socks5Socket, (struct sockaddr*)&clientAddress, &clientAddressLen);
            
            if (clientSocket < 0) {
                log_error("accept() on SOCKS5 socket: %s", strerror(errno));
                continue;
            }

            // SET NON-BLOCKING
            int flags = fcntl(clientSocket, F_GETFL, 0);
            if (flags < 0 || fcntl(clientSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
                log_error("fcntl() failed to set non-blocking mode: %s", strerror(errno));
            }

            char addrBuffer[128];
            printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
            log_info("New SOCKS5 connection from %s", addrBuffer);

            // Handle SOCKS5 connection directly in main thread (no fork)
            handle_socks5_connection(clientSocket, &args);
        }

        // Verificar socket de gestión
        if (FD_ISSET(mgmtSocket, &read_set)) {
            struct sockaddr_storage clientAddress;
            socklen_t clientAddressLen = sizeof(clientAddress);
            int clientSocket = accept(mgmtSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
            
            if (clientSocket < 0) {
                log_error("accept() on management socket: %s", strerror(errno));
                continue;
            }

            // SET NON-BLOCKING
            int flags = fcntl(clientSocket, F_GETFL, 0);
            if (flags < 0 || fcntl(clientSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
                log_error("fcntl() failed to set non-blocking mode: %s", strerror(errno));
            }

            char addrBuffer[128];
            printSocketAddress((struct sockaddr*)&clientAddress, addrBuffer);
            log_info("New management connection from %s", addrBuffer);

            // Handle management connection directly in main thread (no fork)
            handle_management_connection(clientSocket);
        }
    }

    // Limpieza final
    log_info("Server shutting down...");
    close(socks5Socket);
    close(mgmtSocket);
    mgmt_cleanup_shared_memory();

    return 0;
}
