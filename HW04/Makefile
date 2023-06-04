CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pthread -lssl -lcrypto
SERVER_SRC = DTLS_server.c
CLIENT_SRC = DTLS_client.c

all: DTLS_server DTLS_client

DTLS_server:
    $(CC) $(CFLAGS) $(SERVER_SRC) -o DTLS_server

DTLS_client:
    $(CC) $(CFLAGS) $(CLIENT_SRC) -o DTLS_client

clean:
    rm -f DTLS_server DTLS_client
