#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static struct {
    FILE *file;
    log_level level;
    pthread_mutex_t mutex;
} L = {
    .file = NULL,
    .level = LOG_DEFAULT_LEVEL,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

static const char *level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

void logger_init(log_level level, const char *filename) {
    pthread_mutex_lock(&L.mutex);
    if (L.file == NULL) {
        if (filename != NULL) {
            L.file = fopen(filename, "a");
            if (L.file == NULL) {
                perror("[LOGGER] Failed to open log file, using stderr");
                L.file = stderr;
            }
        } else {
            L.file = stderr;
        }
    }
    L.level = level;
    pthread_mutex_unlock(&L.mutex);
}

void logger_set_level(log_level level) {
    pthread_mutex_lock(&L.mutex);
    L.level = level;
    pthread_mutex_unlock(&L.mutex);
}

void logger_close(void) {
    pthread_mutex_lock(&L.mutex);
    if (L.file != NULL && L.file != stderr) {
        fclose(L.file);
    }
    L.file = NULL;
    pthread_mutex_unlock(&L.mutex);
}

void logger_log(log_level level, const char *fmt, ...) {
    if (level < L.level) {
        return;
    }

    pthread_mutex_lock(&L.mutex);

    if (L.file == NULL) {
        // Default to stderr if not initialized
        L.file = stderr;
    }

    // Timestamp
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

    // Message buffer
    char msg_buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    // Print to log file
    if (level >= LOG_ERROR) {
        fprintf(L.file, "%s [%-5s] %s (errno: %s)\n",
                timestamp, level_strings[level], msg_buf, strerror(errno));
    } else {
        fprintf(L.file, "%s [%-5s] %s\n",
                timestamp, level_strings[level], msg_buf);
    }
    fflush(L.file);

    pthread_mutex_unlock(&L.mutex);
}


void log_access(const char *user, const char *status, const char *details_fmt, ...) {
    pthread_mutex_lock(&L.mutex);

    if (L.file == NULL) {
        L.file = stderr;
    }

    // Timestamp
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

    // Details buffer
    char details_buf[512];
    va_list args;
    va_start(args, details_fmt);
    vsnprintf(details_buf, sizeof(details_buf), details_fmt, args);
    va_end(args);

    // Print to log file
    fprintf(L.file, "%s [ACCESS] user='%s' status='%s' details='%s'\n",
            timestamp,
            user ? user : "anonymous",
            status ? status : "N/A",
            details_buf);
    fflush(L.file);

    pthread_mutex_unlock(&L.mutex);
}
