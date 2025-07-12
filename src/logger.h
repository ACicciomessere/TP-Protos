#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

/*
 * Interfaz básica de logger con soporte a múltiples hilos.
 * Todas las funciones son seguras para uso concurrente.
 * El logger está pensado principalmente para registrar eventos
 * relacionados con métricas, aunque puede usarse de forma genérica.
 */

/* Inicializa el logger abriendo el archivo indicado. Si se llama más
 * de una vez, se ignora mientras el logger esté ya inicializado.
 */
void logger_init(const char *filename);

/* Cierra el archivo de log. Debe llamarse al finalizar la aplicación. */
void logger_close(void);

/* Registra un mensaje en el log. Acepta formato printf-like. */
void logger_log(const char *fmt, ...);

#endif // LOGGER_H
