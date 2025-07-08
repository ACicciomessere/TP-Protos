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

#define SOCKS_VERSION 0x05

enum socks5_reply {
    REPLY_SUCCEEDED              = 0x00,
    REPLY_GENERAL_FAILURE        = 0x01,
    REPLY_CONNECTION_NOT_ALLOWED = 0x02,
    REPLY_NETWORK_UNREACHABLE    = 0x03,
    REPLY_HOST_UNREACHABLE       = 0x04,
    REPLY_CONNECTION_REFUSED     = 0x05,
    REPLY_TTL_EXPIRED            = 0x06,
    REPLY_COMMAND_NOT_SUPPORTED  = 0x07,
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
};

int send_socks5_reply(int client_fd, enum socks5_reply code);

int handleClient(int clientSocket, struct socks5args* args);

int handleAuthNegotiation(int clientSocket, struct socks5args* args, char* authenticated_user);
int handleUsernamePasswordAuth(int clientSocket, struct socks5args* args, char* authenticated_user);
int validateUser(const char* username, const char* password, struct socks5args* args);

int handleRequest(int clientSocket, struct addrinfo** addressConnectTo);
int handleConnectAndReply(int clientSocket, struct addrinfo** addressConnectTo, int* remoteSocket);
int handleConnectionData(int clientSocket, int remoteSocket, const char* authenticated_user);

#endif