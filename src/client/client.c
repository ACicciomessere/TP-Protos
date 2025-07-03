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
    printf("ITBA Communication Protocols 2025/1\n");
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
    
    printf("User added: %s\n", user);
    // Here would go the logic to add the user to the server
}

void delete_user(const char* user) {
    printf("User deleted: %s\n", user);
    // Here would go the logic to delete the user from the server
}

void list_users() {
    printf("Configured users:\n");
    printf("  admin\n");
    printf("  user1\n");
    // Here would go the logic to get the real list of users
}

void show_stats() {
    printf("Stats:\n");
    printf("  Total connections: 100\n");
    printf("  Total traffic: 10000 bytes\n");
    printf("  Current users: 5\n");
    printf("  Current connections: 10\n");
    printf("  Current traffic: 1000 bytes\n");
    printf("  Current users: 5\n");
    printf("  Current connections: 10\n");
    printf("  Current traffic: 1000 bytes\n");
    // Here would go the logic to get the real stats
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
