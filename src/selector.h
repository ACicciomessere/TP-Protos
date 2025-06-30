#ifndef SELECTOR_H_CUSTOM_DEFINED
#define SELECTOR_H_CUSTOM_DEFINED

#include <sys/time.h>
#include <stdbool.h>
#include <time.h>

/**
 * Estructura opaca del selector.
 */
typedef struct selector_instance* fd_selector;

/** Códigos de retorno posibles del selector */
typedef enum {
    SELECTOR_SUCCESS = 0,
    SELECTOR_ENOMEM,
    SELECTOR_MAXFD,
    SELECTOR_IARGS,
    SELECTOR_FDINUSE,
    SELECTOR_IO,
} selector_status;

/** Descripción humana del código de error */
const char* selector_strerror(selector_status status);

/** Opciones de configuración inicial del selector */
struct selector_init_config {
    int signal;
    struct timespec select_timeout;
};

/** Inicializa el selector globalmente (registro de señales, etc.) */
selector_status selector_initialize(const struct selector_init_config* config);

/** Limpia recursos globales del selector */
selector_status selector_cleanup(void);

/** Crea una nueva instancia del selector */
fd_selector selector_create(size_t initial_capacity);

/** Libera los recursos de un selector */
void selector_destroy(fd_selector selector);

/** Tipos de interés posibles sobre un descriptor */
typedef enum {
    OP_NOOP  = 0,
    OP_READ  = 1 << 0,
    OP_WRITE = 1 << 2,
} fd_interest;

#define INTEREST_OFF(FLAG, MASK) ((FLAG) & ~(MASK))

/** Argumento que reciben todos los callbacks */
struct selector_key {
    fd_selector s;
    int fd;
    void* data;
};

/** Conjunto de callbacks a registrar para un descriptor */
typedef struct fd_handler {
    void (*handle_read)(struct selector_key* key);
    void (*handle_write)(struct selector_key* key);
    void (*handle_block)(struct selector_key* key);
    void (*handle_close)(struct selector_key* key);
} fd_handler;

/** Registra un descriptor en el selector */
selector_status selector_register(fd_selector s, int fd, const fd_handler* handler, fd_interest interest, void* data);

/** Desregistra un descriptor del selector */
selector_status selector_unregister(fd_selector s, int fd);

/** Cambia los intereses de un descriptor */
selector_status selector_set_interest(fd_selector s, int fd, fd_interest i);

/** Cambia los intereses usando una clave */
selector_status selector_set_interest_key(struct selector_key* key, fd_interest i);

/** Ejecuta una iteración del selector (bloquea hasta evento o timeout) */
selector_status selector_select(fd_selector s);

/** Marca un descriptor como no bloqueante */
int selector_set_nonblocking(int fd);

#endif
