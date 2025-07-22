#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>

#include "core/selector.h"

#define PORT 12345
#define BACKLOG 10

static void accept_connection(struct selector_key *key);
static void handle_client_read(struct selector_key *key);
static void close_client(struct selector_key *key);

static const fd_handler acceptor_handler = {
    .handle_read = accept_connection,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = NULL,
};

static const fd_handler client_handler = {
    .handle_read = handle_client_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = close_client,
};

static void accept_connection(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(key->fd, (struct sockaddr *) &client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept");
        return;
    }

    selector_set_nonblocking(client_fd);

    printf("Nuevo cliente conectado: FD %d\n", client_fd);

    selector_register(key->s, client_fd, &client_handler, OP_READ, NULL);
}

static void handle_client_read(struct selector_key *key) {
    char buffer[128];
    ssize_t n = read(key->fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        printf("Cliente desconectado: FD %d\n", key->fd);
        selector_unregister(key->s, key->fd);
        close(key->fd);
        return;
    }

    buffer[n] = 0;
    printf("Cliente dice: %s\n", buffer);
    write(key->fd, "Hola desde el selector!\n", 25);
}

static void close_client(struct selector_key *key) {
    printf("Cerrando cliente FD %d\n", key->fd);
    close(key->fd);
}

int main(void) {
    struct selector_init_config config = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };

    if (selector_initialize(&config) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Fallo selector_initialize\n");
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };

    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bind(server_fd, (struct sockaddr *) &addr, sizeof(addr));
    listen(server_fd, BACKLOG);

    selector_set_nonblocking(server_fd);

    fd_selector selector = selector_create(1024);
    selector_register(selector, server_fd, &acceptor_handler, OP_READ, NULL);

    while (1) {
        selector_select(selector);
    }

    selector_destroy(selector);
    selector_cleanup();
    return 0;
}
