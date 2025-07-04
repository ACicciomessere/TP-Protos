#include "../shared/shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void show_help(const char* program) {
    printf("Usage: %s [OPTIONS]\n", program);
    printf("\n");
    printf("Client for SOCKS5 proxy management\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -h, --help           Show this help\n");
    printf("  -u, --add-user       Add a user (format: user:password)\n");
    printf("  -d, --del-user       Delete a user\n");
    printf("  -l, --list-users     List configured users\n");
    printf("  -s, --stats          Show statistics of the proxy\n");
    printf("  -v, --version        Show version\n");
    printf("\n");
    printf("SOCKS5 PROXY USAGE:\n");
    printf("  Default server: 127.0.0.1:1080\n");
    printf("  Management: 127.0.0.1:8080\n");
    printf("\n");
}

void show_version() {
    printf("SOCKS5 Proxy Client v1.0\n");
    printf("ITBA Protocolos de Comunicación 2025-1C\n");
}

void add_user(const char* user_pass) {
    char* separator = strchr(user_pass, ':');
    if (separator == NULL) {
        fprintf(stderr, "Error: Formato inválido. Use user:password\n");
        exit(1);
    }
    
    *separator = '\0';
    const char* user = user_pass;
    const char* password = separator + 1;
    
    // Conectar al servidor
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: No se pudo conectar al servidor de gestión\n");
        exit(1);
    }
    
    // Enviar comando
    if (mgmt_send_command(sock, CMD_ADD_USER, user, password) < 0) {
        fprintf(stderr, "Error: No se pudo enviar el comando\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Recibir respuesta
    mgmt_response_t response;
    if (mgmt_receive_response(sock, &response) < 0) {
        fprintf(stderr, "Error: No se pudo recibir la respuesta\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Mostrar resultado
    if (response.success) {
        printf("✓ %s\n", response.message);
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

void delete_user(const char* user) {
    // Conectar al servidor
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: No se pudo conectar al servidor de gestión\n");
        exit(1);
    }
    
    // Enviar comando
    if (mgmt_send_command(sock, CMD_DEL_USER, user, NULL) < 0) {
        fprintf(stderr, "Error: No se pudo enviar el comando\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Recibir respuesta
    mgmt_response_t response;
    if (mgmt_receive_response(sock, &response) < 0) {
        fprintf(stderr, "Error: No se pudo recibir la respuesta\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Mostrar resultado
    if (response.success) {
        printf("✓ %s\n", response.message);
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

void list_users() {
    // Conectar al servidor
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: No se pudo conectar al servidor de gestión\n");
        exit(1);
    }
    
    // Enviar comando
    if (mgmt_send_command(sock, CMD_LIST_USERS, NULL, NULL) < 0) {
        fprintf(stderr, "Error: No se pudo enviar el comando\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Recibir respuesta
    mgmt_response_t response;
    if (mgmt_receive_response(sock, &response) < 0) {
        fprintf(stderr, "Error: No se pudo recibir la respuesta\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Mostrar resultado
    if (response.success) {
        printf("Usuarios configurados (%d):\n", response.user_count);
        for (int i = 0; i < response.user_count; i++) {
            printf("  • %s\n", response.users[i].username);
        }
        if (response.user_count == 0) {
            printf("  (No hay usuarios configurados)\n");
        }
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

void show_stats() {
    // Conectar al servidor
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: No se pudo conectar al servidor de gestión\n");
        exit(1);
    }
    
    // Enviar comando
    if (mgmt_send_command(sock, CMD_STATS, NULL, NULL) < 0) {
        fprintf(stderr, "Error: No se pudo enviar el comando\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Recibir respuesta
    mgmt_response_t response;
    if (mgmt_receive_response(sock, &response) < 0) {
        fprintf(stderr, "Error: No se pudo recibir la respuesta\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Mostrar resultado
    if (response.success) {
        printf("Estadísticas del Proxy SOCKS5:\n");
        printf("  Conexiones totales: %llu\n", response.stats.total_connections);
        printf("  Conexiones actuales: %llu\n", response.stats.current_connections);
        printf("  Bytes transferidos (total): %llu\n", response.stats.total_bytes_transferred);
        printf("  Bytes transferidos (sesión): %llu\n", response.stats.current_bytes_transferred);
        printf("  Usuarios activos: %d\n", response.stats.current_users);
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

int main(int argc, char *argv[]) {
    int option;
    static struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"add-user",  required_argument, 0, 'u'},
        {"del-user",  required_argument, 0, 'd'},
        {"list-users", no_argument,      0, 'l'},
        {"stats",     no_argument,       0, 's'},
        {"version",   no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        show_help(argv[0]);
        return 0;
    }

    while ((option = getopt_long(argc, argv, "hu:d:lsv", long_options, NULL)) != -1) {
        switch (option) {
            case 'h':
                show_help(argv[0]);
                break;
            case 'u':
                add_user(optarg);
                break;
            case 'd':
                delete_user(optarg);
                break;
            case 'l':
                list_users();
                break;
            case 's':
                show_stats();
                break;
            case 'v':
                show_version();
                break;
            default:
                fprintf(stderr, "Opción inválida. Use -h para ayuda.\n");
                return 1;
        }
    }

    return 0;
}
