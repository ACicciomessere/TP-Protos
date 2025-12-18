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
  int waiting_auth_plain_blob; // vimos "AUTH PLAIN" y esperamos la línea Base64
} pop3_state_t;

// Allocate and initialize a new POP3 sniffer state for a connection
pop3_state_t *pop3_sniffer_init(void);

// Free the sniffer state
void pop3_sniffer_destroy(pop3_state_t *state);

// Reset the sniffer state (for reuse)
void pop3_sniffer_reset(pop3_state_t *state);

// Process intercepted data on a POP3 connection (per-connection state)
void pop3_sniffer_process(pop3_state_t *state, const uint8_t *data, size_t len,
                          const char *ip_origen);

// Non-blocking log writer API (for integration with select loop)
int pop3_log_init(void);     // Initialize log writer (open file)
void pop3_log_cleanup(void); // Cleanup log writer (close file)
int pop3_log_get_fd(void);   // Get file descriptor for select (-1 if not open)
int pop3_log_wants_write(void); // Returns 1 if there's pending data to write
int pop3_log_try_flush(
    void); // Non-blocking flush, returns 0 on success/pending, -1 on error

#endif
