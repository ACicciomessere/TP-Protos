#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "protocols/pop3/pop3_sniffer.h"

int main(void) {
    // Create a new sniffer state for this connection
    pop3_state_t *state = pop3_sniffer_init();
    if (state == NULL) {
        printf("Error: could not allocate POP3 sniffer state\n");
        return 1;
    }

    const char* sample_user = "USER testuser\r\n";
    const char* sample_pass = "PASS secret123\r\n";

    // Simulamos el tráfico como si viniera desde el cliente
    pop3_sniffer_process(state, (const uint8_t*)sample_user, strlen(sample_user), "127.0.0.1");
    pop3_sniffer_process(state, (const uint8_t*)sample_pass, strlen(sample_pass), "127.0.0.1");

    printf("Credenciales simuladas procesadas. Revisá pop3_credentials.log.\n");

    // Clean up
    pop3_sniffer_destroy(state);
    return 0;
}
