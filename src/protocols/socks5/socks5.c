#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../shared.h"
#include "../../utils/logger.h"
#include "../../utils/util.h"
#include "socks5.h"

/* Helpers de IO “full” con pequeños timeouts para no quedar colgados (usado por
 * tests/compat) */
static ssize_t recvFull(int fd, void *buf, size_t n, int flags) {
  size_t totalReceived = 0;
  int retries = 0;
  const int maxRetries = 100;

  while (totalReceived < n && retries < maxRetries) {
    ssize_t nowReceived =
        recv(fd, (char *)buf + totalReceived, n - totalReceived, flags);

    if (nowReceived < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
        int poll_result = poll(&pfd, 1, 5000); // 5s

        if (poll_result < 0) {
          log_error("poll() in recvFull: %s", strerror(errno));
          return -1;
        } else if (poll_result == 0) {
          log_error("recv() timeout after 5 seconds");
          return -1;
        } else {
          retries++;
          continue;
        }
      } else {
        log_error("recv(): %s", strerror(errno));
        return -1;
      }
    } else if (nowReceived == 0) {
      if (totalReceived == 0) {
        log_error("Connection closed by peer before any data received");
        return -1;
      } else {
        log_warn(
            "Connection closed by peer, partial data received: %zu/%zu bytes",
            totalReceived, n);
        return (ssize_t)totalReceived;
      }
    } else {
      totalReceived += (size_t)nowReceived;
      retries = 0;
    }
  }

  if (retries >= maxRetries) {
    log_error("recvFull() exceeded maximum retries");
    return -1;
  }

  return (ssize_t)totalReceived;
}

static ssize_t sendFull(int fd, const void *buf, size_t n, int flags) {
  size_t totalSent = 0;
  int retries = 0;
  const int maxRetries = 100;

  while (totalSent < n && retries < maxRetries) {
    ssize_t nowSent =
        send(fd, (const char *)buf + totalSent, n - totalSent, flags);

    if (nowSent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int poll_result = poll(&pfd, 1, 5000); // 5s

        if (poll_result < 0) {
          log_error("poll() in sendFull: %s", strerror(errno));
          return -1;
        } else if (poll_result == 0) {
          log_error("send() timeout after 5 seconds");
          return -1;
        } else {
          retries++;
          continue;
        }
      } else {
        log_error("send(): %s", strerror(errno));
        return -1;
      }
    } else if (nowSent == 0) {
      log_error("send() returned 0, connection may be closed");
      return -1;
    } else {
      totalSent += (size_t)nowSent;
      retries = 0;
    }
  }

  if (retries >= maxRetries) {
    log_error("sendFull() exceeded maximum retries");
    return -1;
  }

  return (ssize_t)totalSent;
}

/* ---- Validación de usuario (archivo + shared memory + args) ---- */
int validateUser(const char *username, const char *password,
                 struct socks5args *args) {
  if (!username || !password) {
    return 0;
  }

  /* 1) auth.db */
  FILE *file = fopen("auth.db", "r");
  if (file != NULL) {
    char line[512];
    while (fgets(line, sizeof(line), file)) {
      char *db_user = strtok(line, ":");
      char *db_pass = strtok(NULL, "\n");
      if (db_user && db_pass) {
        if (strcmp(username, db_user) == 0 && strcmp(password, db_pass) == 0) {
          fclose(file);
          log_access(username, "AUTH_SUCCESS",
                     "User authenticated successfully (auth.db)");
          return 1;
        }
      }
    }
    fclose(file);
  }

  /* 2) memoria compartida */
  shared_data_t *sh = mgmt_get_shared_data();
  if (sh) {
    pthread_mutex_lock(&sh->users_mutex);
    for (int i = 0; i < sh->user_count; i++) {
      if (sh->users[i].active && strcmp(username, sh->users[i].username) == 0 &&
          strcmp(password, sh->users[i].password) == 0) {
        pthread_mutex_unlock(&sh->users_mutex);
        log_access(username, "AUTH_SUCCESS",
                   "User authenticated successfully (shared)");
        return 1;
      }
    }
    pthread_mutex_unlock(&sh->users_mutex);
  }

  /* 3) usuarios de línea de comandos (args) */
  if (args) {
    for (int i = 0; i < MAX_USERS; i++) {
      if (args->users[i].name && args->users[i].pass &&
          args->users[i].name[0] != '\0' && args->users[i].pass[0] != '\0') {
        if (strcmp(username, args->users[i].name) == 0 &&
            strcmp(password, args->users[i].pass) == 0) {
          log_access(username, "AUTH_SUCCESS",
                     "User authenticated successfully (args)");
          return 1;
        }
      }
    }
  }

  log_access(username, "AUTH_FAIL", "Authentication failed for user");
  return 0;
}

/* Helper para enviar una respuesta estándar SOCKS5 */
int send_socks5_reply(int client_fd, enum socks5_reply code) {
  uint8_t response[10];

  response[0] = SOCKS_VERSION; // VER
  response[1] = (uint8_t)code; // REP
  response[2] = 0x00;          // RSV
  response[3] = 0x01;          // ATYP = IPv4 (dummy)
  response[4] = 0x00;          // BND.ADDR = 0.0.0.0
  response[5] = 0x00;
  response[6] = 0x00;
  response[7] = 0x00;
  response[8] = 0x00; // BND.PORT = 0
  response[9] = 0x00;

  ssize_t n = sendFull(client_fd, response, sizeof(response), 0);
  return n == (ssize_t)sizeof(response) ? 0 : -1;
}

/* --- CONNECT robusto (usado por thread / compat) --- */

static int set_nonblocking_fd(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;
  return 0;
}

static enum socks5_reply map_connect_errno_to_reply(int e) {
  switch (e) {
  case ECONNREFUSED:
    return REPLY_CONNECTION_REFUSED;
  case ENETUNREACH:
    return REPLY_NETWORK_UNREACHABLE;
  case EHOSTUNREACH:
    return REPLY_HOST_UNREACHABLE;
  case ETIMEDOUT:
    return REPLY_TTL_EXPIRED;
  default:
    return REPLY_GENERAL_SOCKS_SERVER_FAILURE;
  }
}

int socks5_connect_and_reply(int client_fd, const char *dest_addr,
                             uint16_t dest_port, uint64_t connection_id) {
  if (dest_addr == NULL || dest_addr[0] == '\0' || dest_port == 0) {
    (void)send_socks5_reply(client_fd, REPLY_GENERAL_SOCKS_SERVER_FAILURE);
    return -1;
  }

  log_info("Client requested to connect to %s:%u (fd=%d, id=%llu)", dest_addr,
           dest_port, client_fd, (unsigned long long)connection_id);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_family = AF_UNSPEC;

  char service[6];
  snprintf(service, sizeof(service), "%u", dest_port);

  struct addrinfo *res = NULL;
  int gai = getaddrinfo(dest_addr, service, &hints, &res);
  if (gai != 0 || res == NULL) {
    (void)send_socks5_reply(client_fd, REPLY_HOST_UNREACHABLE);
    return -1;
  }

  int remote_fd = -1;
  enum socks5_reply reply = REPLY_GENERAL_SOCKS_SERVER_FAILURE;

  for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
    remote_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (remote_fd < 0)
      continue;

    int rc = connect(remote_fd, rp->ai_addr, rp->ai_addrlen);
    
    if (rc != 0) {
      reply = map_connect_errno_to_reply(errno);
      close(remote_fd);
      remote_fd = -1;
      continue;
    }

    if (set_nonblocking_fd(remote_fd) < 0) {
      close(remote_fd);
      remote_fd = -1;
      continue;
    }
    reply = REPLY_SUCCEEDED;
    break;
  }

  freeaddrinfo(res);

  if (remote_fd < 0) {
    (void)send_socks5_reply(client_fd, reply);
    return -1;
  }

  if (send_socks5_reply(client_fd, REPLY_SUCCEEDED) < 0) {
    close(remote_fd);
    return -1;
  }

  return remote_fd;
}

/* ------------------------------------------------------------------ */
/* COMPAT: API vieja para tests: lee REQUEST del socket y delega */

int socks5_handle_request(int client_fd, struct socks5args *args,
                          uint64_t connection_id, uint16_t *dest_port_out) {
  (void)args;

  uint8_t hdr[4];
  ssize_t received = recvFull(client_fd, hdr, 4, 0);
  if (received < 0) {
    return -1;
  }

  uint8_t ver = hdr[0];
  uint8_t cmd = hdr[1];
  uint8_t atyp = hdr[3];

  if (ver != SOCKS_VERSION || cmd != 0x01) {
    (void)send_socks5_reply(client_fd, REPLY_COMMAND_NOT_SUPPORTED);
    return -1;
  }

  char dest_addr[256] = {0};
  uint16_t dest_port = 0;

  if (atyp == 0x01) { /* IPv4 */
    struct in_addr addr;
    if (recvFull(client_fd, &addr, sizeof(addr), 0) < 0)
      return -1;

    uint16_t portBuf;
    if (recvFull(client_fd, &portBuf, sizeof(portBuf), 0) < 0)
      return -1;

    dest_port = ntohs(portBuf);
    if (inet_ntop(AF_INET, &addr, dest_addr, sizeof(dest_addr)) == NULL)
      return -1;

  } else if (atyp == 0x03) { /* DOMAIN */
    uint8_t len;
    if (recvFull(client_fd, &len, 1, 0) < 0)
      return -1;

    if (len == 0 || len > 255 || len >= sizeof(dest_addr)) {
      (void)send_socks5_reply(client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
      return -1;
    }

    if (recvFull(client_fd, dest_addr, len, 0) < 0)
      return -1;
    dest_addr[len] = '\0';

    uint16_t portBuf;
    if (recvFull(client_fd, &portBuf, sizeof(portBuf), 0) < 0)
      return -1;

    dest_port = ntohs(portBuf);

  } else if (atyp == 0x04) { /* IPv6 */
    struct in6_addr addr6;
    if (recvFull(client_fd, &addr6, sizeof(addr6), 0) < 0)
      return -1;

    uint16_t portBuf;
    if (recvFull(client_fd, &portBuf, sizeof(portBuf), 0) < 0)
      return -1;

    dest_port = ntohs(portBuf);
    if (inet_ntop(AF_INET6, &addr6, dest_addr, sizeof(dest_addr)) == NULL)
      return -1;

  } else {
    (void)send_socks5_reply(client_fd, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
    return -1;
  }

  if (dest_port_out)
    *dest_port_out = dest_port;

  /* Delegamos el connect+reply al Camino A */
  return socks5_connect_and_reply(client_fd, dest_addr, dest_port,
                                  connection_id);
}
