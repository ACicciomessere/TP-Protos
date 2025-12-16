# Servidor Proxy SOCKS5

Un servidor proxy SOCKS5 completo implementado en C con funcionalidades avanzadas de autenticación, gestión remota y monitoreo de credenciales POP3.

## 📋 Características

- **Proxy SOCKS5 completo** con soporte para IPv4 e IPv6
- **Autenticación de usuarios** con usuario/contraseña
- **Servidor de gestión remota** para administración
- **Sniffer POP3** para monitoreo de credenciales
- **Multiplexado de conexiones** usando `select()`
- **Logging detallado** y métricas de uso
- **Soporte para múltiples conexiones concurrentes**

## 🏗️ Estructura del Proyecto

```
src/
├── main.c              # Servidor principal SOCKS5
├── client.c            # Cliente de gestión remota
├── shared.c/h          # Funciones compartidas
├── core/               # Componentes fundamentales
│   ├── buffer.c/h      # Manejo de buffers
│   ├── selector.c/h    # Multiplexor I/O
│   └── stm.c/h         # Máquina de estados
├── protocols/          # Implementaciones de protocolos
│   ├── socks5/         # Protocolo SOCKS5
│   └── pop3/           # Sniffer POP3
├── utils/              # Utilidades
│   ├── args.c/h        # Parser de argumentos
│   ├── logger.c/h      # Sistema de logging
│   └── util.c/h        # Funciones auxiliares
└── tests/              # Suite de tests
```

## 🚀 Compilación y Ejecución

### Compilar el Proyecto

```bash
# Compilar servidor y cliente
make

# O compilar componentes individuales
make server    # Compila solo el servidor SOCKS5
make client    # Compila solo el cliente de gestión
```

### Targets del Makefile Disponibles

| Target | Descripción |
|--------|-------------|
| `make` o `make all` | Compila servidor y cliente |
| `make server` | Compila el servidor SOCKS5 (`bin/socks5`) |
| `make client` | Compila el cliente de gestión (`bin/client`) |
| `make test` | Compila todos los tests en un ejecutable |
| `make tests` | Compila tests individuales en `test/` |
| `make check-tests` | Compila tests que requieren framework `check` |
| `make clean` | Elimina archivos compilados (`bin/`, `obj/`, `test/`) |

### Ejecutar el Servidor

```bash
# Ejecutar con configuración por defecto
./bin/socks5

# Ejecutar con parámetros personalizados
./bin/socks5 -p 1080 -P 8080 -u usuario:clave -l 0.0.0.0
```

### Ejecutar el Cliente de Gestión

```bash
# Mostrar ayuda
./bin/client -h

# Agregar usuario
./bin/client -u usuario:contraseña

# Listar usuarios
./bin/client -l

# Ver estadísticas
./bin/client -s
```

## 📊 Testing y Rendimiento

### Test de Conexiones Múltiples

Para probar el servidor con múltiples conexiones concurrentes:

```bash
# Iniciar 500 conexiones simultáneas al servidor
for i in {1..500}; do 
  (echo -ne '\x05\x01\x00' | nc localhost 1080 > /dev/null &); 
done

# Verificar conexiones establecidas
netstat -an | grep 1080 | grep ESTABLISHED | wc -l
```

Estos comandos:
1. **Primer comando**: Crea 500 procesos que se conectan al puerto 1080 enviando un handshake SOCKS5 básico
2. **Segundo comando**: Cuenta las conexiones TCP establecidas en el puerto 1080

### Ejecutar Tests Unitarios

```bash
# Compilar y ejecutar tests individuales
make tests
./test/pop3_test     # Test de POP3 sniffer
./test/socks5_tests    # Test del protocolo SOCKS5

## 🔧 Casos de Uso

### Usando cURL a través del Proxy

```bash
curl --socks5 127.0.0.1:1080 --proxy-user usuario:clave https://www.google.com
```

### Usando Netcat a través del Proxy

```bash
ncat --proxy 127.0.0.1:1080 --proxy-type socks5 --proxy-auth user:pass google.com 80
```

### Configuración de Navegadores

Configurar como proxy SOCKS5:
- **Servidor**: `127.0.0.1`
- **Puerto**: `1080`
- **Autenticación**: usuario/contraseña si está configurada

## 📝 Archivos Generados

Durante la ejecución, el servidor genera:

- `metrics.log`: Registro de métricas y eventos del servidor
- `pop3_credentials.log`: Credenciales POP3 capturadas (si está habilitado)
- `auth.db`: Base de datos de autenticación

## 🔒 Seguridad

- Autenticación mediante usuario/contraseña
- Logs detallados de todas las conexiones
- Monitoreo de credenciales POP3 para análisis de seguridad
- Configuración de usuarios limitada (máximo 10)

## 🏋️‍♂️ Pruebas de Stress

A fin de responder a las preguntas de _performance_ y escalabilidad se añadió un
script de _benchmark_ asíncrono que genera miles de sesiones completas contra el
proxy (saludo, autenticación, CONNECT y transferencia HTTP real) y mide la tasa
de transferencias exitosas por segundo.

### Ejecutar una prueba rápida

```bash
# Ejecución todo-en-uno: compila, lanza el servidor con usuario/clave por defecto,
# corre el benchmark C completo y lo detiene
make stress-c                    # usa 1080 por defecto (usuario: pepe / pass: 1234)

# Elegir otro puerto (por ejemplo 12080)
make stress-c STRESS_PORT=12080
```

### Ejecución manual paso a paso

```bash
# 1) Compilar
STRESS_USER=hola STRESS_PASS=123 make stress-c

# 2) Iniciar servidor (en una terminal aparte)
./bin/socks5 -p 1080 &

# 3) Lanzar benchmark (otra terminal)
./bin/stress_socks5 --host 127.0.0.1 --port 1080 \
    --user pepe --pass 1234 \
    --target-host example.org --target-port 80 --path / \
    --total 20000 --concurrency 500 --min-response 2048
```

La herramienta imprime algo como:

```
Total attempted: 20000
Successful transfers: 16344
Duration: 1.187 s
Throughput: 13832.54 connections/sec
Failures: 3656
```

Significado de los campos:
* **Total attempted**: cantidad de sesiones completas iniciadas.  
* **Successful transfers**: sesiones que completaron greeting + auth + CONNECT + descarga mínima.  
* **Duration**: tiempo total de la prueba.  
* **Throughput**: `Successful/Duration` (sesiones/s).  
* **Failures**: `Total - Successful` (sesiones abortadas o con respuesta insuficiente).
