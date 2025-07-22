/** selector.c - multiplexor de entrada/salida adaptado */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include "selector.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DEFAULT_ERROR_MSG "Unhandled selector error"

const char* selector_strerror(const selector_status status) {
    switch (status) {
        case SELECTOR_SUCCESS: return "Success";
        case SELECTOR_ENOMEM: return "Memory allocation failed";
        case SELECTOR_MAXFD: return "Too many file descriptors";
        case SELECTOR_IARGS: return "Invalid argument";
        case SELECTOR_IO: return "I/O error";
        default: return DEFAULT_ERROR_MSG;
    }
}

static void noop_handler(int signal) {
    // usado solo para interrumpir pselect
}

static struct selector_init_config global_config;
static sigset_t signal_block_set, signal_empty_set;

selector_status selector_initialize(const struct selector_init_config* config) {
    memcpy(&global_config, config, sizeof(global_config));
    selector_status status = SELECTOR_SUCCESS;

    struct sigaction action = {
        .sa_handler = noop_handler,
    };

    sigemptyset(&signal_block_set);
    sigaddset(&signal_block_set, config->signal);

    if (sigprocmask(SIG_BLOCK, &signal_block_set, NULL) == -1) {
        return SELECTOR_IO;
    }

    if (sigaction(config->signal, &action, NULL) == -1) {
        return SELECTOR_IO;
    }

    sigemptyset(&signal_empty_set);
    return status;
}

selector_status selector_cleanup(void) {
    return SELECTOR_SUCCESS;
}

struct descriptor_entry {
    int fd;
    fd_interest interest;
    const fd_handler* callbacks;
    void* context;
};

struct selector_instance {
    struct descriptor_entry* entries;
    size_t capacity;
    int highest_fd;
    fd_set read_master, write_master;
    fd_set read_temp, write_temp;
    struct timespec default_timeout;
};

static const int UNUSED_FD = -1;

static void initialize_entry(struct descriptor_entry* entry) {
    entry->fd = UNUSED_FD;
}

static int find_max_fd(struct selector_instance* sel) {
    int max_fd = 0;
    for (int i = 0; i <= sel->highest_fd; i++) {
        if (sel->entries[i].fd != UNUSED_FD && sel->entries[i].fd > max_fd) {
            max_fd = sel->entries[i].fd;
        }
    }
    return max_fd;
}

static void update_fd_sets(struct selector_instance* sel, struct descriptor_entry* entry) {
    FD_CLR(entry->fd, &sel->read_master);
    FD_CLR(entry->fd, &sel->write_master);

    if (entry->interest & OP_READ) {
        FD_SET(entry->fd, &sel->read_master);
    }
    if (entry->interest & OP_WRITE) {
        FD_SET(entry->fd, &sel->write_master);
    }
}

#define MAX_DESCRIPTORS FD_SETSIZE

static selector_status expand_capacity(struct selector_instance* sel, size_t new_count) {
    if (new_count > MAX_DESCRIPTORS) {
        return SELECTOR_MAXFD;
    }

    size_t new_size = sizeof(struct descriptor_entry) * new_count;
    struct descriptor_entry* new_entries = realloc(sel->entries, new_size);
    if (!new_entries) {
        return SELECTOR_ENOMEM;
    }

    size_t old_count = sel->capacity;
    sel->entries = new_entries;
    sel->capacity = new_count;

    for (size_t i = old_count; i < new_count; ++i) {
        initialize_entry(&sel->entries[i]);
    }

    return SELECTOR_SUCCESS;
}

fd_selector selector_create(size_t initial_capacity) {
    struct selector_instance* sel = calloc(1, sizeof(*sel));
    if (!sel) return NULL;

    sel->default_timeout = global_config.select_timeout;
    if (expand_capacity(sel, initial_capacity) != SELECTOR_SUCCESS) {
        free(sel);
        return NULL;
    }

    return sel;
}

void selector_destroy(fd_selector selector) {
    if (selector) {
        free(selector->entries);
        free(selector);
    }
}

selector_status selector_register(fd_selector selector, int fd, const fd_handler* handler, fd_interest interest, void* context) {
    if (!selector || !handler || fd < 0 || fd >= MAX_DESCRIPTORS) return SELECTOR_IARGS;

    if ((size_t)fd >= selector->capacity) {
        if (expand_capacity(selector, fd + 1) != SELECTOR_SUCCESS) return SELECTOR_ENOMEM;
    }

    struct descriptor_entry* entry = &selector->entries[fd];
    if (entry->fd != UNUSED_FD) return SELECTOR_IO;

    entry->fd = fd;
    entry->callbacks = handler;
    entry->interest = interest;
    entry->context = context;

    if (fd > selector->highest_fd) selector->highest_fd = fd;

    update_fd_sets(selector, entry);
    return SELECTOR_SUCCESS;
}

selector_status selector_unregister(fd_selector selector, int fd) {
    if (!selector || fd < 0 || fd >= MAX_DESCRIPTORS) return SELECTOR_IARGS;

    struct descriptor_entry* entry = &selector->entries[fd];
    if (entry->fd == UNUSED_FD) return SELECTOR_IARGS;

    if (entry->callbacks && entry->callbacks->handle_close) {
        struct selector_key key = { .s = selector, .fd = fd, .data = entry->context };
        entry->callbacks->handle_close(&key);
    }

    FD_CLR(fd, &selector->read_master);
    FD_CLR(fd, &selector->write_master);
    initialize_entry(entry);
    selector->highest_fd = find_max_fd(selector);
    return SELECTOR_SUCCESS;
}

selector_status selector_select(fd_selector selector) {
    if (!selector) return SELECTOR_IARGS;

    memcpy(&selector->read_temp, &selector->read_master, sizeof(fd_set));
    memcpy(&selector->write_temp, &selector->write_master, sizeof(fd_set));
    struct timespec timeout = selector->default_timeout;

    int result = pselect(selector->highest_fd + 1,
                         &selector->read_temp,
                         &selector->write_temp,
                         NULL,
                         &timeout,
                         &signal_empty_set);

    if (result < 0) {
        if (errno == EINTR || errno == EAGAIN) return SELECTOR_SUCCESS;
        return SELECTOR_IO;
    }

    for (int fd = 0; fd <= selector->highest_fd; ++fd) {
        struct descriptor_entry* entry = &selector->entries[fd];
        if (entry->fd == UNUSED_FD) continue;

        struct selector_key key = { .s = selector, .fd = fd, .data = entry->context };

        if ((entry->interest & OP_READ) && FD_ISSET(fd, &selector->read_temp)) {
            if (entry->callbacks && entry->callbacks->handle_read) {
                entry->callbacks->handle_read(&key);
            }
        }
        if ((entry->interest & OP_WRITE) && FD_ISSET(fd, &selector->write_temp)) {
            if (entry->callbacks && entry->callbacks->handle_write) {
                entry->callbacks->handle_write(&key);
            }
        }
    }

    return SELECTOR_SUCCESS;
}

int selector_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
