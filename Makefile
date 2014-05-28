
CC = gcc
CLIBS = -lcrypto
CFLAGS = -Wall -O3
SOURCES= cpor-gen-keys.c cpor-tag-file.c cpor-gen-challenge.c cpor-calc-response.c cpor-verify-response.c
TARGETS= cpor-gen-keys cpor-tag-file cpor-gen-challenge cpor-calc-response cpor-verify-response

all: $(TARGETS)

cpor-gen-keys: cpor-gen-keys.o
	$(CC) $(CLIBS) $< -o $@

cpor-tag-file: cpor-tag-file.o
	$(CC) $(CLIBS) $< -o $@

cpor-gen-challenge: cpor-gen-challenge.o
	$(CC) $(CLIBS) $< -o $@

cpor-calc-response: cpor-calc-response.o
	$(CC) $(CLIBS) $< -o $@

cpor-verify-response: cpor-verify-response.o
	$(CC) $(CLIBS) $< -o $@

%.o: %.c cpor.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -f *.o $(TARGETS)
	@rm -f master_keys *.metadata *.tag *.challenge *.response
