# Protocolos implementados

## SOCKS5

El servidor implementa el handshake estándar de SOCKS5 con soporte para autenticación de usuario/contraseña (método 0x02) y el comando CONNECT. Las etapas son:

| Etapa | Request del cliente | Respuesta del servidor | Notas |
|-------|---------------------|------------------------|-------|
| Greeting | `VER | NMETHODS | METHODS` | `0x05 0x02` (se fuerza username/password) | Solo aceptamos `VER=5`. |
| Autenticación (RFC 1929) | `VER | ULEN | UNAME | PLEN | PASS` | `0x01 0x00` éxito / `0x01 0x01` fallo | Las credenciales se comparan contra la tabla de usuarios en memoria compartida. |
| Request CONNECT | `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT` | `VER=0x05, REP=0x00, RSV=0x00, ATYP=BND.ADDR, DST.PORT=BND.PORT` | Soportamos IPv4 (`ATYP=0x01`), dominios (`0x03`) e IPv6 (`0x04`). El timeout de resolución se controla desde management. |
| Relay de datos | flujo crudo | flujo crudo | El trafico se multiplexa con `select()` y se contabiliza en las métricas. Si el destino es el puerto 110 y los disectores están habilitados, los payloads se envían al sniffer POP3. |

### Opciones / parámetros relevantes
- **Autenticación**: en la línea de comandos se pasan hasta 10 usuarios (`-u user:pass`). También pueden agregarse o eliminarse vía management (`CMD_ADD_USER`/`CMD_DEL_USER`).
- **Timeout de resolución/conexión**: configurable con `CMD_SET_TIMEOUT` (valor en ms). Por defecto 10 segundos.
- **Buffers de relay**: `CMD_SET_BUFFER` permite ajustar el tamaño del búfer circular usado en el relay (entre 512 y 65536 bytes). El valor se aplica en caliente a todas las conexiones.
- **Disectores**: se activan/desactivan con `CMD_ENABLE_DISSECTORS` / `CMD_DISABLE_DISSECTORS`.

### Respuestas de error (`REP`)
El servidor usa los códigos oficiales de SOCKS5:
- `0x01`: fallo general.
- `0x02`: regla de red no permitida.
- `0x03`: red inalcanzable.
- `0x04`: host inalcanzable (se usa cuando `getaddrinfo` falla).
- `0x05`: conexión rechazada.
- `0x06`: TTL expirado.
- `0x07`: comando no soportado (cuando `CMD != 0x01`).
- `0x08`: tipo de dirección no soportado.

### Estado interno
Cada conexión se maneja con una mini–máquina de estados (`STATE_GREETING → STATE_AUTH → STATE_REQUEST → STATE_RELAYING`). Los descriptores se registran en `select()` con intereses de lectura/escritura según haya datos pendientes.

### Disectores POP3
- El sniffer solo inspecciona sesiones cuyo destino es el puerto `110`. Cuando detecta `USER`/`PASS`, el hallazgo se escribe en `pop3_credentials.log` y se replica en `metrics.log` (`log_info [POP3] Captured credentials…`).
- Los disectores están habilitados por defecto salvo que el servidor se inicie con `./bin/socks5 -N`, en cuyo caso quedan desactivados de forma permanente.
- En cualquier momento pueden habilitarse o deshabilitarse desde el protocolo de gestión mediante `CMD_ENABLE_DISSECTORS` / `CMD_DISABLE_DISSECTORS` (por ejemplo `./bin/client --enable-dissectors`).
- Cuando el estado cambia se deja traza explícita en los logs para que quede constancia de si se están inspeccionando credenciales y dónde se almacenan.

## Protocolo de gestión

La API de gestión se sirve por TCP y usa estructuras binarias fijas definidas en `shared.h` (`mgmt_message_t` y respuestas específicas por comando). Un cliente debe enviar un `mgmt_message_t` completo y recibirá la estructura de respuesta asociada al comando:

- `CMD_ADD_USER` / `CMD_DEL_USER`: envían/reciben `mgmt_simple_response_t`.
- `CMD_LIST_USERS`: recibe `mgmt_users_response_t`.
- `CMD_STATS`: recibe `mgmt_stats_response_t`.
- `CMD_SET_TIMEOUT`, `CMD_SET_BUFFER`, `CMD_SET_MAX_CLIENTS`, `CMD_ENABLE_DISSECTORS`, `CMD_DISABLE_DISSECTORS`, `CMD_RELOAD_CONFIG`, `CMD_GET_CONFIG`: consumen o devuelven las estructuras homónimas.

- Todas las solicitudes tienen el formato `mgmt_message_t` y solo admiten ASCII (se rellenan con ceros). El campo `username` se reutiliza para argumentos numéricos (por ejemplo, `CMD_SET_BUFFER` espera el tamaño en bytes como string decimal).
- Las respuestas son estructuras fijas (`mgmt_simple_response_t`, `mgmt_users_response_t`, etc.) enviadas con `send_all`/`recv_all` para garantizar que se transmiten todas las bytes.
- Cada conexión se atiende en un hilo dedicado. Tras procesar un comando se cierra el socket.

### Estabilidad de la ABI
Los `struct` definidos en `shared.h` forman la ABI del protocolo de gestión; cualquier cambio debe reflejarse en este documento y en los clientes CLI (`src/client.c`). Actualmente el layout es:

```
mgmt_message_t {
    mgmt_command_t command;   // enum (32 bits)
    char username[64];
    char password[64];
}
```

Los comandos de respuesta reutilizan `mgmt_simple_response_t` (`success` + `message[1024]`) o los específicos (`mgmt_stats_response_t`, `mgmt_config_response_t`, etc.).
