include ./Makefile.inc

SERVER_SOURCES=$(filter-out src/test.c src/server/main.c src/server/main_nonblocking.c src/stm_test.c src/buffer_test.c src/netutils_test.c src/parser_test.c src/parser_utils_test.c, $(wildcard src/*.c src/server/*.c))
SERVER_NB_SOURCES=$(filter-out src/test.c src/server/main.c src/server/main_nonblocking.c src/stm_test.c src/buffer_test.c src/netutils_test.c src/parser_test.c src/parser_utils_test.c, $(wildcard src/*.c src/server/*.c))
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)
TEST_SOURCES=src/test.c src/selector.c

OBJECTS_FOLDER=./obj
OUTPUT_FOLDER=./bin

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o) obj/server/main.o
SERVER_NB_OBJECTS=$(SERVER_NB_SOURCES:src/%.c=obj/%.o) obj/server/main_nonblocking.o
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)
TEST_OBJECTS=$(TEST_SOURCES:src/%.c=obj/%.o)

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5
SERVER_NB_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5nb
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client
TEST_OUTPUT_FILE=$(OUTPUT_FOLDER)/test

all: server server-nb client

server: $(SERVER_OUTPUT_FILE)
server-nb: $(SERVER_NB_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
test: $(TEST_OUTPUT_FILE)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(SERVER_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_OUTPUT_FILE)

$(SERVER_NB_OUTPUT_FILE): $(SERVER_NB_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(SERVER_NB_OBJECTS) $(SHARED_OBJECTS) -o $(SERVER_NB_OUTPUT_FILE)

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS) -o $(CLIENT_OUTPUT_FILE)

$(TEST_OUTPUT_FILE): $(TEST_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $(TEST_OBJECTS) -o $(TEST_OUTPUT_FILE)

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

obj/%.o: src/%.c
	mkdir -p $(OBJECTS_FOLDER)/server
	mkdir -p $(OBJECTS_FOLDER)/client
	mkdir -p $(OBJECTS_FOLDER)/shared
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

.PHONY: all server server-nb client test clean
