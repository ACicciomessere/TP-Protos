#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <netdb.h>
#include "../../utils/args.h"
#include "../../shared.h"

/* Versión SOCKS soportada */
#define SOCKS_VERSION           0x05

/* Métodos de autenticación SOCKS5 (RFC 1928 / RFC 1929) */
#define SOCKS5_AUTH_NONE            0x00
#define SOCKS5_AUTH_GSSAPI          0x01
#define SOCKS5_AUTH_USERPASS        0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE   0xFF

/* Códigos de respuesta (REP) del protocolo SOCKS5 */
enum socks5_reply {
    REPLY_SUCCEEDED                      = 0x00,
    REPLY_GENERAL_SOCKS_SERVER_FAILURE   = 0x01,
    REPLY_CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02,
    REPLY_NETWORK_UNREACHABLE            = 0x03,
    REPLY_HOST_UNREACHABLE               = 0x04,
    REPLY_CONNECTION_REFUSED             = 0x05,
    REPLY_TTL_EXPIRED                    = 0x06,
    REPLY_COMMAND_NOT_SUPPORTED          = 0x07,
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED     = 0x08
};

/* Validación de usuario (archivo, shared memory, args) */
int validateUser(const char* username, const char* password, struct socks5args* args);

/* Handshake por etapas (no bloqueante desde el punto de vista del main) */
int socks5_handle_greeting(int client_fd,
                           struct socks5args *args,
                           uint64_t connection_id);

/* Devuelve siguiente estado (STATE_REQUEST) o <0 en error */
int socks5_handle_auth(int client_fd,
                       struct socks5args *args,
                       uint64_t connection_id);

/*
 * Request + resolución + connect.
 * Bloqueante, pero el main lo llama desde un thread.
 * Devuelve:
 *   - fd del remoto >= 0 en éxito
 *   - <0 en error
 * Además, si dest_port_out != NULL, escribe allí el puerto destino.
 */
int socks5_handle_request(int client_fd,
                          struct socks5args *args,
                          uint64_t connection_id,
                          uint16_t *dest_port_out);

/* Helper para enviar una respuesta estándar SOCKS5 */
int send_socks5_reply(int client_fd, enum socks5_reply code);

#endif
