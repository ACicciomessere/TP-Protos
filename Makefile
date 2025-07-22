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
# Tests que usan framework check
CHECK_TESTS=src/tests/buffer_test.c src/tests/stm_test.c
# Tests con main propio
MAIN_TESTS=$(filter-out $(CHECK_TESTS), $(TEST_INDIVIDUAL_SOURCES))

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

all: server client

server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
test: $(TEST_OUTPUT_FILE)

# Compilar tests individuales
tests: $(MAIN_TESTS:src/tests/%.c=$(TEST_FOLDER)/%)

# Compilar tests que requieren check (opcional)
check-tests: $(CHECK_TESTS:src/tests/%.c=$(TEST_FOLDER)/%)

# Objetos del servidor sin main para tests que los necesiten
TEST_SERVER_OBJECTS:=$(filter-out obj/main.o, $(SERVER_OBJECTS))

# Regla para tests con main propio
$(TEST_FOLDER)/%: src/tests/%.c $(SHARED_OBJECTS) $(TEST_SERVER_OBJECTS)
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -I src $(LDFLAGS) $< $(SHARED_OBJECTS) $(TEST_SERVER_OBJECTS) -o $@

# Regla para tests que usan check (necesitan linkeo con check)
$(TEST_FOLDER)/buffer_test: src/tests/buffer_test.c $(SHARED_OBJECTS)
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -I src $(LDFLAGS) $< $(filter-out obj/core/buffer.o, $(SHARED_OBJECTS)) -lcheck -lm -lpthread -lrt -lsubunit -o $@

$(TEST_FOLDER)/stm_test: src/tests/stm_test.c $(SHARED_OBJECTS)
	mkdir -p $(TEST_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) -I src $(LDFLAGS) $< $(SHARED_OBJECTS) -lcheck -lm -lpthread -lrt -lsubunit -o $@

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
