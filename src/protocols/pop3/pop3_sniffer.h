#ifndef POP3_SNIFFER_H
#define POP3_SNIFFER_H

#include <stddef.h>
#include <stdint.h>

// Procesa datos interceptados en una conexión hacia un servidor POP3
void pop3_sniffer_process(const uint8_t *data, size_t len, const char *ip_origen);

// Reset the sniffer state for a new connection
void pop3_sniffer_reset(void);

#endif 
