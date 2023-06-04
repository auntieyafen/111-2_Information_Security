#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

void handle_error(const char* error_msg) {
    fprintf(stderr, "%s\n", error_msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

typedef struct {
    SSL* ssl;
    int sockfd;
} client_info;

void* handle_client(void* arg) {
    client_info* client = (client_info*)arg;
    char buffer[BUFFER_SIZE];
    int len;

    while (1) {
        len = SSL_read(client->ssl, buffer, sizeof(buffer));
        if (len > 0) {
            // Echo back to the client
            SSL_write(client->ssl, buffer, len); 
        } else {
            int error = SSL_get_error(client->ssl, len);
            if (error == SSL_ERROR_ZERO_RETURN) {
                printf("Client disconnected.\n");
            } else {
                handle_error("DTLS read error.");
            }
            break;
        }
    }

    // Close the connection
    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    close(client->sockfd);
    free(client);

    return NULL;
}

int main() {
    // Initialize the OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create a DTLS context
    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        handle_error("Failed to create DTLS context.");
    }

    // Load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        handle_error("Failed to load server certificate.");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        handle_error("Failed to load server private key.");
    }

    // Create a UDP socket and bind to a specific port
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(12345);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Failed to bind socket.");
    }

    // Create an array to hold client threads
    pthread_t client_threads[MAX_CLIENTS];
    int num_clients = 0;

    // Accept incoming DTLS connections
    while (1) {
        // Accept a new connection
        int client_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sockfd < 0) {
            handle_error("Failed to accept client connection.");
        }

        // Create a new SSL structure for the connection
        SSL* ssl = SSL_new(ctx);
        if (!ssl) {
            handle_error("Failed to create SSL structure.");
        }

        // Set the client socket as the underlying I/O for the SSL structure
        if (SSL_set_fd(ssl, client_sockfd) == 0) {
            handle_error("Failed to set client socket for SSL structure.");
        }

        // Perform the DTLS handshake
        if (SSL_accept(ssl) <= 0) {
            handle_error("DTLS handshake error.");
        }

        // Create a client_info struct to store the client SSL and socket information
        client_info* client = (client_info*)malloc(sizeof(client_info));
        client->ssl = ssl;
        client->sockfd = client_sockfd;

        // Create a new thread to handle the client
        pthread_create(&client_threads[num_clients], NULL, handle_client, (void*)client);
        num_clients++;
    }

    // Wait for all client threads to finish
    for (int i = 0; i < num_clients; i++) {
        pthread_join(client_threads[i], NULL);
    }

    // Cleanup and close the server
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}
