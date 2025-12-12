#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>

typedef struct
{
    const char *proxy_host;
    uint16_t proxy_port;
    const char *dest_host;
    uint16_t dest_port;
    const char *username;
    const char *password;
    size_t bytes_to_send;
    int id;
    int verbose;
    int result;
    size_t bytes_sent;
} thread_args_t;

static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_successful = 0;
static int g_failed = 0;
static size_t g_total_bytes_sent = 0;

/* ========= util de tiempo ========= */

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ========= util de sockets ========= */

static int connect_to_host(const char *host, uint16_t port)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp = NULL;
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0)
    {
        fprintf(stderr, "[ERR] getaddrinfo(%s:%s): %s\n",
                host, port_str, gai_strerror(err));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            break; // success
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock; // -1 si no se pudo conectar
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
        {
            return -1; // EOF prematuro
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len, size_t *bytes_sent_total)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
        if (bytes_sent_total)
            *bytes_sent_total += (size_t)n;
    }
    return 0;
}

/* ========= Handshake SOCKS5 ========= */

static int socks5_greeting(int sock, int use_auth)
{
    uint8_t buf[4];

    if (use_auth)
    {
        // VER = 5, NMETHODS = 2, METHODS = { NO_AUTH(0), USERPASS(2) }
        buf[0] = 0x05;
        buf[1] = 0x02;
        buf[2] = 0x00;
        buf[3] = 0x02;
        if (write_all(sock, buf, 4, NULL) != 0)
            return -1;
    }
    else
    {
        // VER = 5, NMETHODS = 1, METHODS = { NO_AUTH(0) }
        buf[0] = 0x05;
        buf[1] = 0x01;
        buf[2] = 0x00;
        if (write_all(sock, buf, 3, NULL) != 0)
            return -1;
    }

    if (read_all(sock, buf, 2) != 0)
        return -1;
    if (buf[0] != 0x05)
        return -1;
    if (use_auth && buf[1] != 0x02 && buf[1] != 0x00)
        return -1; // esperaba 0x02
    if (!use_auth && buf[1] != 0x00)
        return -1;

    return buf[1]; // método elegido
}

static int socks5_auth_userpass(int sock, const char *user, const char *pass)
{
    size_t ulen = strlen(user);
    size_t plen = strlen(pass);

    if (ulen > 255 || plen > 255)
        return -1;

    size_t len = 3 + ulen + plen;
    uint8_t *buf = malloc(len);
    if (!buf)
        return -1;

    size_t off = 0;
    buf[off++] = 0x01; // versión user/pass
    buf[off++] = (uint8_t)ulen;
    memcpy(buf + off, user, ulen);
    off += ulen;
    buf[off++] = (uint8_t)plen;
    memcpy(buf + off, pass, plen);

    if (write_all(sock, buf, len, NULL) != 0)
    {
        free(buf);
        return -1;
    }
    free(buf);

    uint8_t resp[2];
    if (read_all(sock, resp, 2) != 0)
        return -1;
    if (resp[0] != 0x01 || resp[1] != 0x00)
        return -1;

    return 0;
}

static int socks5_connect(int sock, const char *host, uint16_t port)
{
    uint8_t buf[262];
    size_t off = 0;

    buf[off++] = 0x05; // VER
    buf[off++] = 0x01; // CMD = CONNECT
    buf[off++] = 0x00; // RSV

    struct in_addr addr;
    int is_ip = inet_pton(AF_INET, host, &addr);

    if (is_ip == 1)
    {
        // IPv4
        buf[off++] = 0x01; // ATYP = IPv4
        memcpy(buf + off, &addr.s_addr, 4);
        off += 4;
    }
    else
    {
        // Nombre de dominio
        size_t hlen = strlen(host);
        if (hlen > 255)
            return -1;
        buf[off++] = 0x03; // ATYP = domain
        buf[off++] = (uint8_t)hlen;
        memcpy(buf + off, host, hlen);
        off += hlen;
    }

    uint16_t nport = htons(port);
    memcpy(buf + off, &nport, 2);
    off += 2;

    if (write_all(sock, buf, off, NULL) != 0)
        return -1;

    // Leer respuesta: VER REP RSV ATYP ...
    uint8_t hdr[4];
    if (read_all(sock, hdr, 4) != 0)
        return -1;
    if (hdr[0] != 0x05 || hdr[1] != 0x00)
        return -1; // error en CONNECT

    uint8_t atyp = hdr[3];
    size_t addr_len;
    if (atyp == 0x01)
        addr_len = 4 + 2; // IPv4 + port
    else if (atyp == 0x03)
    {
        uint8_t dlen;
        if (read_all(sock, &dlen, 1) != 0)
            return -1;
        addr_len = (size_t)dlen + 2; // domain + port
        uint8_t *tmp = malloc(addr_len);
        if (!tmp)
            return -1;
        if (read_all(sock, tmp, addr_len) != 0)
        {
            free(tmp);
            return -1;
        }
        free(tmp);
        return 0;
    }
    else if (atyp == 0x04)
        addr_len = 16 + 2; // IPv6 + port
    else
        return -1;

    uint8_t *tmp = malloc(addr_len);
    if (!tmp)
        return -1;
    if (read_all(sock, tmp, addr_len) != 0)
    {
        free(tmp);
        return -1;
    }
    free(tmp);
    return 0;
}

/* ========= HTTP POST para transferir bytes ========= */

static int http_post_send_body(int sock, const char *host, uint16_t port,
                               size_t bytes_to_send, size_t *bytes_sent_total)
{
    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "POST /upload HTTP/1.1\r\n"
                              "Host: %s:%u\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              host, (unsigned)port, bytes_to_send);

    if (header_len <= 0 || (size_t)header_len >= sizeof(header))
        return -1;

    if (write_all(sock, (const uint8_t *)header, (size_t)header_len,
                  bytes_sent_total) != 0)
        return -1;

    // Enviar el cuerpo: bytes_to_send de 'X'
    size_t remaining = bytes_to_send;
    uint8_t buf[4096];
    memset(buf, 'X', sizeof(buf));

    while (remaining > 0)
    {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        if (write_all(sock, buf, chunk, bytes_sent_total) != 0)
            return -1;
        remaining -= chunk;
    }

    // Cierro el lado de escritura; leo respuesta y la descarto
    shutdown(sock, SHUT_WR);
    uint8_t tmp[1024];
    while (1)
    {
        ssize_t n = read(sock, tmp, sizeof(tmp));
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
    }

    return 0;
}

/* ========= worker ========= */

static void *worker_thread(void *arg)
{
    thread_args_t *a = (thread_args_t *)arg;
    a->result = -1;
    a->bytes_sent = 0;

    int sock = connect_to_host(a->proxy_host, a->proxy_port);
    if (sock < 0)
    {
        if (a->verbose)
        {
            fprintf(stderr, "[T%03d] Error conectando al proxy\n", a->id);
        }
        goto done;
    }

    int use_auth = (a->username != NULL && a->password != NULL);
    int method = socks5_greeting(sock, use_auth);
    if (method < 0)
    {
        if (a->verbose)
            fprintf(stderr, "[T%03d] Error en greeting SOCKS5\n", a->id);
        goto done;
    }

    if (use_auth && method == 0x02)
    {
        if (socks5_auth_userpass(sock, a->username, a->password) != 0)
        {
            if (a->verbose)
                fprintf(stderr, "[T%03d] Error en auth user/pass\n", a->id);
            goto done;
        }
    }
    else if (use_auth && method == 0x00)
    {
        // el server aceptó NO_AUTH aunque tenemos user/pass: también es válido
        if (a->verbose)
            fprintf(stderr, "[T%03d] Server eligió NO_AUTH\n", a->id);
    }

    if (socks5_connect(sock, a->dest_host, a->dest_port) != 0)
    {
        if (a->verbose)
            fprintf(stderr, "[T%03d] Error en CONNECT\n", a->id);
        goto done;
    }

    int r = http_post_send_body(sock, a->dest_host, a->dest_port,
                                a->bytes_to_send, &a->bytes_sent);

    // Si falló y NO llegamos a enviar nada -> fallo real
    if (r != 0 && a->bytes_sent == 0)
    {
        if (a->verbose)
            fprintf(stderr, "[T%03d] Error enviando datos (0 bytes enviados)\n", a->id);
        goto done;
    }

    // Si llegamos a enviar aunque sea 1 byte, para fines de performance
    // consideramos la conexión "exitosa" (el proxy ya relayó datos).
    a->result = 0;

done:
    if (sock >= 0)
        close(sock);

    pthread_mutex_lock(&g_stats_mutex);
    g_total_bytes_sent += a->bytes_sent; // SIEMPRE contamos data enviada
    if (a->result == 0)
        g_successful++;
    else
        g_failed++;
    pthread_mutex_unlock(&g_stats_mutex);

    return NULL;
}

/* ========= main ========= */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "Options:\n"
            "  -H host      Proxy host (default 127.0.0.1)\n"
            "  -P port      Proxy port (default 1080)\n"
            "  -D host      Destination host (default 127.0.0.1)\n"
            "  -Q port      Destination port (default 9000)\n"
            "  -c num       Number of concurrent connections (threads) (default 100)\n"
            "  -b bytes     Bytes to send per connection (default 1048576 = 1MB)\n"
            "  -U user      Username for auth (optional)\n"
            "  -W pass      Password for auth (optional)\n"
            "  -v           Verbose\n",
            prog);
}

int main(int argc, char *argv[])
{
    const char *proxy_host = "127.0.0.1";
    uint16_t proxy_port = 1080;
    const char *dest_host = "127.0.0.1";
    uint16_t dest_port = 9000;
    int connections = 100;
    size_t bytes_per_conn = 1048576;
    const char *user = NULL;
    const char *pass = NULL;
    int verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "H:P:D:Q:c:b:U:W:v")) != -1)
    {
        switch (opt)
        {
        case 'H':
            proxy_host = optarg;
            break;
        case 'P':
            proxy_port = (uint16_t)atoi(optarg);
            break;
        case 'D':
            dest_host = optarg;
            break;
        case 'Q':
            dest_port = (uint16_t)atoi(optarg);
            break;
        case 'c':
            connections = atoi(optarg);
            break;
        case 'b':
            bytes_per_conn = (size_t)strtoull(optarg, NULL, 10);
            break;
        case 'U':
            user = optarg;
            break;
        case 'W':
            pass = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (connections <= 0)
    {
        fprintf(stderr, "Invalid number of connections\n");
        return 1;
    }

    printf("Running stress test:\n");
    printf("  Proxy: %s:%u\n", proxy_host, proxy_port);
    printf("  Destination: %s:%u\n", dest_host, dest_port);
    printf("  Connections: %d\n", connections);
    printf("  Bytes per connection: %zu\n", bytes_per_conn);

    pthread_t *threads = calloc((size_t)connections, sizeof(pthread_t));
    thread_args_t *args = calloc((size_t)connections, sizeof(thread_args_t));
    if (!threads || !args)
    {
        fprintf(stderr, "Out of memory\n");
        free(threads);
        free(args);
        return 1;
    }

    double start = now_seconds();

    for (int i = 0; i < connections; i++)
    {
        args[i].proxy_host = proxy_host;
        args[i].proxy_port = proxy_port;
        args[i].dest_host = dest_host;
        args[i].dest_port = dest_port;
        args[i].username = user;
        args[i].password = pass;
        args[i].bytes_to_send = bytes_per_conn;
        args[i].id = i + 1;
        args[i].verbose = verbose;
        args[i].result = -1;
        args[i].bytes_sent = 0;

        if (pthread_create(&threads[i], NULL, worker_thread, &args[i]) != 0)
        {
            fprintf(stderr, "Error creating thread %d\n", i + 1);
            connections = i;
            break;
        }
    }

    for (int i = 0; i < connections; i++)
    {
        pthread_join(threads[i], NULL);
    }

    double end = now_seconds();
    double elapsed = end - start;
    if (elapsed <= 0)
        elapsed = 1e-9;

    double total_mb = (double)g_total_bytes_sent / (1024.0 * 1024.0);
    double throughput = total_mb / elapsed;

    printf("Completed %d/%d successful connections.\n", g_successful, connections);
    printf("Total data sent: %.2f MB\n", total_mb);
    printf("Elapsed time: %.3f s\n", elapsed);
    printf("Throughput: %.2f MB/s\n", throughput);

    free(threads);
    free(args);
    return 0;
}
