#ifndef _UTIL_H_
#define _UTIL_H_

#include <netdb.h>
#include <sys/socket.h>

int printSocketAddress(const struct sockaddr* address, char* addrBuffer);

const char* printFamily(struct addrinfo* aip);
const char* printType(struct addrinfo* aip);
const char* printProtocol(struct addrinfo* aip);

/**
 * Imprime textualmente los flags de un addrinfo
 */
void printFlags(struct addrinfo* aip, char* buffer, size_t buffer_size);

char* printAddressPort(const struct addrinfo* aip, char addr[]);

// Determina si dos sockets son iguales (misma direccion y puerto)
int sockAddrsEqual(const struct sockaddr* addr1, const struct sockaddr* addr2);

#endif
