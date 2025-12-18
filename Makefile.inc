COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -g -pthread -Wno-pointer-arith -DNDEBUG

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	COMPILERFLAGS += -lrt
endif 

LDFLAGS=
