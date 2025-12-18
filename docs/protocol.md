# Protocolos implementados

Este documento describe formalmente los protocolos implementados por el servidor proxy desarrollado para el Trabajo Práctico de Protocolos de Comunicación. Incluye el protocolo SOCKS5, los disectores POP3 y el protocolo propietario de gestión y monitoreo.

---

## 1. Protocolo SOCKS5

El servidor implementa el protocolo SOCKS5 conforme a los RFC 1928 y 1929. Se soporta autenticación obligatoria mediante usuario/contraseña (método `0x02`) y el comando `CONNECT` para el establecimiento de conexiones TCP hacia destinos IPv4, IPv6 o FQDN.

### 1.1 Etapas del protocolo

**Greeting**  
El cliente inicia la comunicación enviando:
```
VER | NMETHODS | METHODS
```
El servidor responde seleccionando el método de autenticación.

**Autenticación (RFC 1929)**  
Si se selecciona autenticación usuario/contraseña, el cliente envía:
```
VER | ULEN | UNAME | PLEN | PASSWD
```
El servidor valida las credenciales y responde indicando éxito o fallo.

**Request CONNECT**  
Una vez autenticado, el cliente solicita la conexión enviando:
```
VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
```
Solo se soporta el comando `CONNECT` (`CMD = 0x01`).

**Relay de datos**  
Tras una respuesta exitosa, el servidor relay­a tráfico bidireccional entre cliente y destino. El flujo es multiplexado con `select()` y contabilizado en las métricas del sistema. Si el destino es el puerto TCP 110 y los disectores están habilitados, los payloads se envían al sniffer POP3.

---

### 1.2 Opciones y parámetros relevantes

- **Autenticación**: se pueden configurar hasta 10 usuarios al iniciar el servidor mediante `-u user:pass`, o dinámicamente vía gestión (CMD_ADD_USER / CMD_DEL_USER).
- **Timeout de resolución/conexión**: configurable mediante CMD_SET_TIMEOUT (milisegundos). Valor por defecto: 10 segundos.
- **Buffers de relay**: CMD_SET_BUFFER permite ajustar en caliente el tamaño del buffer circular (entre 512 y 65536 bytes).
- **Disectores**: se controlan mediante CMD_ENABLE_DISSECTORS y CMD_DISABLE_DISSECTORS.

---

### 1.3 Respuestas de error (REP)

El servidor utiliza los códigos oficiales de SOCKS5:

- `0x01`: fallo general.
- `0x02`: regla de red no permitida.
- `0x03`: red inalcanzable.
- `0x04`: host inalcanzable (fallo de `getaddrinfo()`).
- `0x05`: conexión rechazada.
- `0x06`: TTL expirado.
- `0x07`: comando no soportado.
- `0x08`: tipo de dirección no soportado.

---

### 1.4 Estado interno

Cada conexión se maneja mediante una máquina de estados finita:

```
STATE_GREETING → STATE_AUTH → STATE_REQUEST → STATE_RELAYING
```

Los descriptores se registran dinámicamente en el `select()` principal según los intereses de lectura y escritura de cada conexión.

---

## 2. Disectores POP3

El sniffer POP3 inspecciona únicamente sesiones cuyo destino es el puerto TCP 110. Durante el relay de datos se detectan los mecanismos de autenticación `USER/PASS` y `AUTH PLAIN`, decodificando el payload Base64 cuando corresponde.

Las credenciales capturadas se registran en `pop3_credentials.log` y se emite una traza informativa en `metrics.log`.

Los disectores están habilitados por defecto. Si el servidor se inicia con la opción `-N`, quedan deshabilitados permanentemente. En tiempo de ejecución pueden habilitarse o deshabilitarse mediante CMD_ENABLE_DISSECTORS / CMD_DISABLE_DISSECTORS, dejando constancia en los logs.

---

## 3. Protocolo de gestión y monitoreo

El sistema implementa un protocolo propietario de gestión servido sobre TCP en el puerto **8080** (configurable). Utiliza estructuras binarias de tamaño fijo definidas en `shared.h`.

> **Nota:** El protocolo de gestión es **100% no-bloqueante**, integrado en el loop principal del servidor mediante `pselect()`. Las conexiones de gestión se manejan sin hilos dedicados.

Cada solicitud consiste en el envío de una estructura `mgmt_message_t`, seguida por la recepción de la estructura de respuesta asociada al comando.

### 3.1 Comandos soportados

- CMD_ADD_USER / CMD_DEL_USER → `mgmt_simple_response_t`
- CMD_LIST_USERS → `mgmt_users_response_t`
- CMD_STATS → `mgmt_stats_response_t`
- CMD_SET_TIMEOUT
- CMD_SET_BUFFER
- CMD_SET_MAX_CLIENTS
- CMD_ENABLE_DISSECTORS / CMD_DISABLE_DISSECTORS
- CMD_RELOAD_CONFIG
- CMD_GET_CONFIG

Todos los comandos utilizan el formato base `mgmt_message_t` y admiten únicamente ASCII. Los campos no utilizados se rellenan con ceros. El campo `username` se reutiliza para argumentos numéricos cuando corresponde.

Las respuestas se envían de forma no-bloqueante y se garantiza la transmisión completa mediante buffers internos. Cada conexión de gestión se cierra automáticamente al finalizar el comando.

---

## 4. Estabilidad de la ABI

Las estructuras definidas en `shared.h` constituyen la ABI del protocolo de gestión. Cualquier modificación debe reflejarse en este documento y en los clientes que consumen la API.

Layout actual:

```
mgmt_message_t {
    mgmt_command_t command;   // enum (32 bits)
    char username[64];
    char password[64];
}
```

Las respuestas reutilizan `mgmt_simple_response_t` o estructuras específicas como `mgmt_stats_response_t` y `mgmt_config_response_t`.

