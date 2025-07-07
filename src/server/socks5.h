#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include <netdb.h>
#include "../args.h"

// Authentication methods
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_FAIL 0xFF

// Username/password authentication status codes
#define SOCKS5_USERPASS_SUCCESS 0x00
#define SOCKS5_USERPASS_FAIL 0x01

int handleClient(int clientSocket, struct socks5args* args);

int handleAuthNegotiation(int clientSocket, struct socks5args* args);
int handleUsernamePasswordAuth(int clientSocket, struct socks5args* args);
int validateUser(const char* username, const char* password, struct socks5args* args);

int handleRequest(int clientSocket, struct addrinfo** addressConnectTo);
int handleConnectAndReply(int clientSocket, struct addrinfo** addressConnectTo, int* remoteSocket);
int handleConnectionData(int clientSocket, int remoteSocket);

#endif