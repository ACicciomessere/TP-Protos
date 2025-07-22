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

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

.PHONY: all server client test tests check-tests clean

# Uso de targets de tests:
# make tests       - Compila tests individuales con main() en carpeta ./test/
# make check-tests - Compila tests que requieren framework 'check' (opcional)
# make test        - Compila todos los tests en un solo ejecutable (original)

STRESS_PORT ?= 1080

TOOLS_FOLDER=tools
STRESS_C_SOURCES=$(TOOLS_FOLDER)/stress_socks5.c
STRESS_C_BINARY=$(OUTPUT_FOLDER)/stress_socks5

$(STRESS_C_BINARY): $(STRESS_C_SOURCES)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -O2 -std=c11 -pthread $< -o $@

stress-c: server $(STRESS_C_BINARY)
	@echo "[STRESS-C] Launching SOCKS5 server on port $(STRESS_PORT) in background..."
	@./bin/socks5 -p $(STRESS_PORT) & \
	SERVER_PID=$$!; \
	sleep 1; \
	$(STRESS_C_BINARY) --host 127.0.0.1 --port $(STRESS_PORT) --total 20000 --concurrency 1000; \
	STATUS=$$?; \
	echo "[STRESS-C] Stopping server (PID=$$SERVER_PID)"; \
	kill $$SERVER_PID 2>/dev/null || true; \
	exit $$STATUS

.PHONY: stress-c
