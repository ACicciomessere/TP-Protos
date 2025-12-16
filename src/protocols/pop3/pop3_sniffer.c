#define _POSIX_C_SOURCE 200809L

#include "pop3_sniffer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include "../../utils/logger.h"

// Structure to hold state for each connection
typedef struct {
    char user[256];
    char pass[256];
    char buffer[1024];
    size_t buffer_len;
    int user_found;
    int pass_found;
} pop3_state_t;

static pop3_state_t pop3_state = {0};

// Helper function to trim whitespace and newlines
static char* trim(char* str) {
    if (!str) return NULL;
    
    // Remove trailing whitespace and newlines
    char* end = str + strlen(str) - 1;
    while (end > str && (isspace(*end) || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    
    // Remove leading whitespace
    while (*str && isspace(*str)) str++;
    
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
    
    for (int i = 0; upper_data[i]; i++) upper_data[i] = toupper(upper_data[i]);
    for (int i = 0; upper_command[i]; i++) upper_command[i] = toupper(upper_command[i]);
    
    const char* cmd_pos = strstr(upper_data, upper_command);
    if (!cmd_pos) return NULL;
    
    // Calculate the offset in the original string
    size_t offset = cmd_pos - upper_data;
    const char* original_cmd_pos = data + offset;
    
    // Move past the command in the original string
    original_cmd_pos += strlen(command);
    
    // Skip leading whitespace
    while (*original_cmd_pos && isspace(*original_cmd_pos)) original_cmd_pos++;
    
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

// Log credentials with timestamp and IP
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
        
        // Replicamos el hallazgo en el logger principal para que quede trazabilidad en metrics.log
        log_info("[POP3] Captured credentials from %s (USER=%s, PASS=%s)", ip_origen,
                 username, password);
    } else {
        log_error("[POP3] Could not open pop3_credentials.log for writing: %s", strerror(errno));
    }
}

// Reset state for a new connection
void pop3_sniffer_reset(void) {
    memset(&pop3_state, 0, sizeof(pop3_state));
}

// Process POP3 data with improved parsing
void pop3_sniffer_process(const uint8_t *data, size_t len, const char *ip_origen) {
    if (len == 0 || data == NULL) return;

    // Add data to buffer
    if (pop3_state.buffer_len + len >= sizeof(pop3_state.buffer)) {
        // Buffer overflow, reset
        pop3_state.buffer_len = 0;
    }
    
    memcpy(pop3_state.buffer + pop3_state.buffer_len, data, len);
    pop3_state.buffer_len += len;
    pop3_state.buffer[pop3_state.buffer_len] = '\0';

    // Process complete lines
    char* line_start = pop3_state.buffer;
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
                upper_line[i] = toupper(upper_line[i]);
            }
            
            // Check for USER command (case insensitive)
            if (strncmp(upper_line, "USER ", 5) == 0 && !pop3_state.user_found) {
                char* username = extract_value(trimmed_line, "USER");
                if (username) {
                    strncpy(pop3_state.user, username, sizeof(pop3_state.user) - 1);
                    pop3_state.user[sizeof(pop3_state.user) - 1] = '\0';
                    pop3_state.user_found = 1;
                    printf("[POP3 SNIFFER] Found USER: %s\n", pop3_state.user);
                    free(username);
                }
            }
            // Check for PASS command (case insensitive)
            else if (strncmp(upper_line, "PASS ", 5) == 0 && !pop3_state.pass_found) {
                char* password = extract_value(trimmed_line, "PASS");
                if (password) {
                    strncpy(pop3_state.pass, password, sizeof(pop3_state.pass) - 1);
                    pop3_state.pass[sizeof(pop3_state.pass) - 1] = '\0';
                    pop3_state.pass_found = 1;
                    printf("[POP3 SNIFFER] Found PASS: %s\n", pop3_state.pass);
                    free(password);
                }
            }
        }
        
        line_start = line_end + 1;
    }

    // If we have both user and password, log them
    if (pop3_state.user_found && pop3_state.pass_found) {
        log_credentials(pop3_state.user, pop3_state.pass, ip_origen);
        
        // Reset state for next credentials
        pop3_state.user_found = 0;
        pop3_state.pass_found = 0;
        memset(pop3_state.user, 0, sizeof(pop3_state.user));
        memset(pop3_state.pass, 0, sizeof(pop3_state.pass));
    }

    // Move remaining data to beginning of buffer
    if (line_start < pop3_state.buffer + pop3_state.buffer_len) {
        size_t remaining = pop3_state.buffer + pop3_state.buffer_len - line_start;
        memmove(pop3_state.buffer, line_start, remaining);
        pop3_state.buffer_len = remaining;
        pop3_state.buffer[pop3_state.buffer_len] = '\0';
    } else {
        pop3_state.buffer_len = 0;
    }
}
