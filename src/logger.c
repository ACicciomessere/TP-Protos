#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// Puntero al archivo de log
static FILE *log_file = NULL;
// Mutex para asegurar acceso concurrente seguro
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void open_log_file_if_needed(void) {
    if (log_file == NULL) {
        // Por defecto se usa "metrics.log" si no se inicializó explícitamente
        log_file = fopen("metrics.log", "a");
        if (log_file == NULL) {
            // Si falla, enviamos a stderr como fallback
            perror("[ERR] No se pudo abrir el archivo de log");
            log_file = stderr;
        }
    }
}

void logger_init(const char *filename) {
    pthread_mutex_lock(&log_mutex);
    if (log_file == NULL) {
        log_file = fopen(filename, "a");
        if (log_file == NULL) {
            perror("[ERR] No se pudo abrir el archivo de log");
            log_file = stderr;
        }
    }
    pthread_mutex_unlock(&log_mutex);
}

void logger_close(void) {
    pthread_mutex_lock(&log_mutex);
    if (log_file != NULL && log_file != stderr) {
        fclose(log_file);
    }
    log_file = NULL;
    pthread_mutex_unlock(&log_mutex);
}

void logger_log(const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);

    open_log_file_if_needed();

    /* Timestamp */
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

    /* Primero calculamos el tamaño del mensaje formateado del usuario */
    va_list args;
    va_start(args, fmt);
    int msg_len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (msg_len < 0) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    /* Tamaño total: timestamp + brackets + espacio + mensaje + newline + nul */
    size_t total_len = strlen(timestamp) + 3 /*[] */ + 1 /*space*/ + (size_t)msg_len + 1 /*\n*/ + 1 /*nul*/;
    char *buffer = (char *)malloc(total_len);
    if (buffer == NULL) {
        /* Si no hay memoria, escribimos de manera tradicional */
        fprintf(log_file, "[%s] ", timestamp);
        va_start(args, fmt);
        vfprintf(log_file, fmt, args);
        va_end(args);
        fputc('\n', log_file);
        fflush(log_file);
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    /* Construimos la línea completa */
    size_t offset = 0;
    offset += snprintf(buffer + offset, total_len - offset, "[%s] ", timestamp);
    va_start(args, fmt);
    offset += vsnprintf(buffer + offset, total_len - offset, fmt, args);
    va_end(args);
    buffer[offset++] = '\n';
    buffer[offset] = '\0';

    /* Escribimos de una sola vez */
    fputs(buffer, log_file);
    fflush(log_file);

    free(buffer);
    pthread_mutex_unlock(&log_mutex);
}
