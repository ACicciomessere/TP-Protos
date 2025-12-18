include ./Makefile.inc

# Agrupamos fuentes por sub-módulo para poder combinarlas sin duplicar
CORE_SOURCES=$(wildcard src/core/*.c)
UTIL_SOURCES=$(wildcard src/utils/*.c)
PROTOCOL_SOURCES=$(wildcard src/protocols/*/*.c)
SRC_ROOT_SOURCES=$(wildcard src/*.c)

# Fuentes compartidas entre servidor y cliente
SHARED_SOURCES=$(CORE_SOURCES) $(UTIL_SOURCES) src/shared.c

# Fuentes exclusivas del servidor (todo menos el cliente y los tests)
SERVER_SOURCES=$(filter-out src/client.c src/shared.c $(wildcard src/tests/*.c), $(SRC_ROOT_SOURCES)) $(PROTOCOL_SOURCES)

# Fuente del cliente de gestión
CLIENT_SOURCES=src/client.c

# Fuentes de test
TEST_SOURCES=$(wildcard src/tests/*.c)

# Tests individuales
TEST_INDIVIDUAL_SOURCES=$(wildcard src/tests/*.c)
# Tests con main propio
MAIN_TESTS=$(TEST_INDIVIDUAL_SOURCES)

OBJECTS_FOLDER=./obj
OUTPUT_FOLDER=./bin
TEST_FOLDER=./test

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)
TEST_OBJECTS=$(TEST_SOURCES:src/%.c=obj/%.o)

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client
TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/test

all: server client tests

# Optional tools (kept in C to avoid external dependencies like python/matplotlib)
tools: $(OUTPUT_FOLDER)/sink_server $(OUTPUT_FOLDER)/plot_stress $(OUTPUT_FOLDER)/stress_client

server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
test: $(TEST_OUTPUT_FILE)

# Compilar tests individuales
tests: $(MAIN_TESTS:src/tests/%.c=$(TEST_FOLDER)/%)

# Objetos del servidor sin main para tests que los necesiten
TEST_SERVER_OBJECTS:=$(filter-out obj/main.o, $(SERVER_OBJECTS))

# Regla para tests con main propio
$(TEST_FOLDER)/%: src/tests/%.c $(SHARED_OBJECTS) $(TEST_SERVER_OBJECTS)
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -I src $(LDFLAGS) $< $(SHARED_OBJECTS) $(TEST_SERVER_OBJECTS) -o $@

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

$(TEST_OUTPUT_FILE): $(TEST_OBJECTS) $(TEST_SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(TEST_OBJECTS) $(TEST_SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(TEST_OUTPUT_FILE)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)
	rm -rf $(TEST_FOLDER)
	rm -f auth.db
	rm -f $(OUTPUT_FOLDER)/sink_server_stress_*

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

.PHONY: all server client test tests check-tests clean tools stress

TOOLS_FOLDER=tools

SINK_C_SOURCES=$(TOOLS_FOLDER)/sink_server.c
SINK_BINARY=$(OUTPUT_FOLDER)/sink_server

PLOT_C_SOURCES=$(TOOLS_FOLDER)/plot_stress.c
PLOT_BINARY=$(OUTPUT_FOLDER)/plot_stress

STRESS_CLIENT_SOURCES=src/tests/stress_client.c
STRESS_CLIENT_BINARY=$(OUTPUT_FOLDER)/stress_client

$(SINK_BINARY): $(SINK_C_SOURCES)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -O2 -std=c11 -pthread $< -o $@

$(PLOT_BINARY): $(PLOT_C_SOURCES)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -O2 -std=c11 $< -o $@

$(STRESS_CLIENT_BINARY): $(STRESS_CLIENT_SOURCES)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -O2 -std=c11 -pthread $< -o $@

# Uso de targets de tests:
# make tests       - Compila tests individuales con main() en carpeta ./test/
# make check-tests - Compila tests que requieren framework 'check' (opcional)
# make test        - Compila todos los tests en un solo ejecutable (original)

.PHONY: tools

# =============================================================================
# Stress test target using stress_client
# Usage: make stress [STRESS_CONNS=500] [STRESS_BYTES=1048576]
#        make stress STRESS_SOCKS_PORT=1081 STRESS_SINK_PORT=8889
# =============================================================================

STRESS_CONNS      ?= 500
STRESS_BYTES      ?= 1048576
STRESS_USER       ?= testuser
STRESS_PASS       ?= testpass
STRESS_HOST       ?= 127.0.0.1

STRESS_SOCKS_PORT ?= 1080
STRESS_SINK_PORT  ?= 8888

# Flags extra opcionales para socks5 (ej: -v)
SOCKS_FLAGS ?=

stress: server tools
	@set -e; \
	HOST="$(STRESS_HOST)"; \
	SOCKS_PORT="$(STRESS_SOCKS_PORT)"; \
	SINK_PORT="$(STRESS_SINK_PORT)"; \
	CONNS="$(STRESS_CONNS)"; \
	BYTES="$(STRESS_BYTES)"; \
	USER="$(STRESS_USER)"; \
	PASS="$(STRESS_PASS)"; \
	SOCKS_FLAGS="$(SOCKS_FLAGS)"; \
	\
	SOCKS_BIN="$(SERVER_OUTPUT_FILE)"; \
	STRESS_BIN="$(STRESS_CLIENT_BINARY)"; \
	SINK_BIN="$(OUTPUT_FOLDER)/sink_server_stress_$$SINK_PORT"; \
	\
	echo "[STRESS] Checking required binaries..."; \
	test -x "$$SOCKS_BIN"; \
	test -x "$$STRESS_BIN"; \
	\
	echo "[STRESS] Writing auth.db..."; \
	echo "$$USER:$$PASS" > auth.db; \
	\
	echo "[STRESS] Ensuring ports are free (SOCKS=$$SOCKS_PORT, SINK=$$SINK_PORT)..."; \
	if ss -lnt "( sport = :$$SOCKS_PORT )" | grep -q LISTEN; then \
		echo "[STRESS][ERR] Port $$SOCKS_PORT already in use (SOCKS)."; \
		exit 1; \
	fi; \
	if ss -lnt "( sport = :$$SINK_PORT )" | grep -q LISTEN; then \
		echo "[STRESS][ERR] Port $$SINK_PORT already in use (sink_server)."; \
		exit 1; \
	fi; \
	\
	echo "[STRESS] Building sink_server for port $$SINK_PORT..."; \
	gcc -Wall -pedantic -g -pthread -Wno-pointer-arith -lrt -O2 -std=c11 -pthread \
		-DSINK_PORT=$$SINK_PORT -DSINK_BIND_ADDR="\"127.0.0.1\"" \
		tools/sink_server.c -o "$$SINK_BIN"; \
	chmod +x "$$SINK_BIN"; \
	\
	echo "[STRESS] Starting sink_server on $$HOST:$$SINK_PORT..."; \
	"$$SINK_BIN" >/dev/null 2>&1 & \
	SINK_PID=$$!; \
	sleep 1; \
	\
	echo "[STRESS] Starting SOCKS5 server on $$HOST:$$SOCKS_PORT..."; \
	"$$SOCKS_BIN" -u "$$USER:$$PASS" -p "$$SOCKS_PORT" $$SOCKS_FLAGS >/dev/null 2>&1 & \
	SOCKS_PID=$$!; \
	sleep 2; \
	\
	trap 'kill $$SINK_PID $$SOCKS_PID 2>/dev/null || true' EXIT INT TERM; \
	\
	echo "[STRESS] Running stress test ($$CONNS connections, $$BYTES bytes each)..."; \
	echo ""; \
	"$$STRESS_BIN" -H "$$HOST" -P "$$SOCKS_PORT" -D "$$HOST" -Q "$$SINK_PORT" \
		-c "$$CONNS" -b "$$BYTES" -U "$$USER" -W "$$PASS"; \
	echo ""; \
	echo "[STRESS] Done."
