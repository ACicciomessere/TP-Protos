#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

/*
 * Improved, thread-safe logger interface with severity levels.
 */

// Definition of log levels
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL,
} log_level;

#define LOG_DEFAULT_LEVEL LOG_INFO

/*
 * Initializes the logger.
 *  - level: Minimum log level to be recorded.
 *  - filename: Log file. If NULL, stderr will be used.
 */
void logger_init(log_level level, const char *filename);

/* Changes the log level at runtime. */
void logger_set_level(log_level level);

/* Closes the log file. Must be called at application shutdown. */
void logger_close(void);

/*
 * Logs a generic log message.
 * It is preferable to use the helper macros (log_info, log_debug, etc.).
 */
void logger_log(log_level level, const char *fmt, ...);


/*
 * Logs a user access event.
 * Format: [timestamp] [ACCESS] user='...' status='...' details='...'
 *  - user: Name of the user performing the action (can be NULL for anonymous).
 *  - status: A string describing the result (e.g., "OK", "FAIL_AUTH", "FAIL_CONNECT").
 *  - details: Additional details, such as the connection destination.
 */
void log_access(const char *user, const char *status, const char *details_fmt, ...);


/* Macros to facilitate logging */
#define log_debug(...) logger_log(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)  logger_log(LOG_INFO,  __VA_ARGS__)
#define log_warn(...)  logger_log(LOG_WARN,  __VA_ARGS__)
#define log_error(...) logger_log(LOG_ERROR, __VA_ARGS__)
#define log_fatal(...) logger_log(LOG_FATAL, __VA_ARGS__)


#endif // LOGGER_H
