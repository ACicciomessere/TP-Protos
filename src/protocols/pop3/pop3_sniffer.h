#ifndef POP3_SNIFFER_H
#define POP3_SNIFFER_H

#include <stddef.h>
#include <stdint.h>

// Structure to hold state for each connection (per-connection sniffer)
typedef struct {
    char user[256];
    char pass[256];
    char buffer[1024];
    size_t buffer_len;
    int user_found;
    int pass_found;

    // Para AUTH PLAIN (SASL)
    int waiting_auth_plain_blob;   // vimos "AUTH PLAIN" y esperamos la línea Base64
} pop3_state_t;

// Allocate and initialize a new POP3 sniffer state for a connection
pop3_state_t *pop3_sniffer_init(void);

// Free the sniffer state
void pop3_sniffer_destroy(pop3_state_t *state);

// Reset the sniffer state (for reuse)
void pop3_sniffer_reset(pop3_state_t *state);

// Process intercepted data on a POP3 connection (per-connection state)
void pop3_sniffer_process(pop3_state_t *state, const uint8_t *data, size_t len, const char *ip_origen);

#endif 
