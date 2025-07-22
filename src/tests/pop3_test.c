#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "protocols/pop3/pop3_sniffer.h"

int main(void) {
    pop3_sniffer_reset();

    const char* sample_user = "USER testuser\r\n";
    const char* sample_pass = "PASS secret123\r\n";

    // Simulamos el tráfico como si viniera desde el cliente
    pop3_sniffer_process((const uint8_t*)sample_user, strlen(sample_user), "127.0.0.1");
    pop3_sniffer_process((const uint8_t*)sample_pass, strlen(sample_pass), "127.0.0.1");

    printf("Credenciales simuladas procesadas. Revisá pop3_credentials.log.\n");
    return 0;
}
