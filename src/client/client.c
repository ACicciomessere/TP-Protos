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

void show_version(void) {
    printf("SOCKS5 Proxy Client v1.0\n");
    printf("ITBA Protocolos de Comunicación 2025-1C\n");
}

void add_user(const char* user_pass) {
    char* separator = strchr(user_pass, ':');
    if (separator == NULL) {
        fprintf(stderr, "Error: Invalid format. Use user:password\n");
        exit(1);
    }
    
    *separator = '\0';
    const char* user = user_pass;
    const char* password = separator + 1;
    
    // Connect to server
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: Could not connect to management server\n");
        exit(1);
    }
    
    // Send command
    if (mgmt_send_command(sock, CMD_ADD_USER, user, password) < 0) {
        fprintf(stderr, "Error: Could not send command\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Receive response
    mgmt_simple_response_t response;
    if (mgmt_receive_simple_response(sock, &response) < 0) {
        fprintf(stderr, "Error: Could not receive response\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Show result
    if (response.success) {
        printf("✓ %s\n", response.message);
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

void delete_user(const char* user) {
    // Connect to server
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: Could not connect to management server\n");
        exit(1);
    }
    
    // Send command
    if (mgmt_send_command(sock, CMD_DEL_USER, user, NULL) < 0) {
        fprintf(stderr, "Error: Could not send command\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Receive response
    mgmt_simple_response_t response;
    if (mgmt_receive_simple_response(sock, &response) < 0) {
        fprintf(stderr, "Error: Could not receive response\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Show result
    if (response.success) {
        printf("✓ %s\n", response.message);
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

void list_users(void) {
    // Connect to server
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: Could not connect to management server\n");
        exit(1);
    }
    
    // Send command
    if (mgmt_send_command(sock, CMD_LIST_USERS, NULL, NULL) < 0) {
        fprintf(stderr, "Error: Could not send command\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Receive response
    mgmt_users_response_t response;
    if (mgmt_receive_users_response(sock, &response) < 0) {
        fprintf(stderr, "Error: Could not receive response\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Show result
    if (response.success) {
        printf("Configured users (%d):\n", response.user_count);
        for (int i = 0; i < response.user_count; i++) {
            printf("  • %s\n", response.users[i].username);
        }
        if (response.user_count == 0) {
            printf("  (No users configured)\n");
        }
    } else {
        printf("✗ %s\n", response.message);
    }
    
    mgmt_close_connection(sock);
}

void show_stats(void) {
    // Connect to server
    int sock = mgmt_connect_to_server();
    if (sock < 0) {
        fprintf(stderr, "Error: Could not connect to management server\n");
        exit(1);
    }
    
    // Send command
    if (mgmt_send_command(sock, CMD_STATS, NULL, NULL) < 0) {
        fprintf(stderr, "Error: Could not send command\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Receive response
    mgmt_stats_response_t response;
    if (mgmt_receive_stats_response(sock, &response) < 0) {
        fprintf(stderr, "Error: Could not receive response\n");
        mgmt_close_connection(sock);
        exit(1);
    }
    
    // Show result
    if (response.success) {
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("                    PROXY STATISTICS\n");
        printf("═══════════════════════════════════════════════════════════════\n\n");
        
        // General proxy statistics
        printf("📊 GENERAL STATISTICS:\n");
        printf("  • Total connections: %llu\n", response.stats.total_connections);
        printf("  • Current connections: %llu\n", response.stats.current_connections);
        printf("  • Peak concurrent connections: %llu\n", response.stats.peak_concurrent_connections);
        
        printf("  • Bytes transferred (total): %llu\n", response.stats.total_bytes_transferred);
        printf("  • Bytes transferred (session): %llu\n", response.stats.current_bytes_transferred);
        
        // Show number of configured users
        printf("  • Configured users: %d\n", response.user_count);
        
        // Show server uptime
        time_t current_time = time(NULL);
        if (response.stats.server_start_time > 0) {
            int uptime = current_time - response.stats.server_start_time;
            int days = uptime / 86400;
            int hours = (uptime % 86400) / 3600;
            int minutes = (uptime % 3600) / 60;
            int seconds = uptime % 60;
            printf("  • Uptime: %dd %02dh %02dm %02ds\n", days, hours, minutes, seconds);
        }
        
        if (response.stats.total_connections > 0) {
            uint64_t avg_bytes = response.stats.total_bytes_transferred / response.stats.total_connections;
            printf("  • Average per connection: %llu bytes\n", avg_bytes);
        }
        
        printf("\n═══════════════════════════════════════════════════════════════\n");
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
                fprintf(stderr, "Invalid option. Use -h for help.\n");
                return 1;
        }
    }

    return 0;
}
