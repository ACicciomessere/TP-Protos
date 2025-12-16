COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -g -pthread -Wno-pointer-arith

ifneq ($(shell uname -s),Darwin)
	COMPILERFLAGS += -lrt
endif 

LDFLAGS=
