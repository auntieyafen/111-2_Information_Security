#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

void handle_error(const char* error_msg) {
    fprintf(stderr, "%s\n", error_msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void dtls_client_echo() {
    // Initialize the OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create a DTLS context
    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        handle_error("Failed to create DTLS context.");
    }

    // Create a UDP socket
    int sockfd;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        handle_error("Failed to create socket.");
    }

    // Configure the server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    if (inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr)) <= 0) {
        handle_error("Failed to configure server address.");
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Failed to connect to the server.");
    }

    // Create a new SSL structure for the connection
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        handle_error("Failed to create SSL structure.");
    }

    // Set the UDP socket as the underlying I/O for the SSL structure
    SSL_set_fd(ssl, sockfd);

    // Perform the DTLS handshake
    if (SSL_connect(ssl) <= 0) {
        handle_error("DTLS handshake error.");
    }

    // Send and receive messages from the server
    char buffer[BUFFER_SIZE];
    int len;
    while (1) {
        printf("Enter message: ");
        fgets(buffer, sizeof(buffer), stdin);
        len = strlen(buffer);

        if (SSL_write(ssl, buffer, len) <= 0) {
            handle_error("DTLS write error.");
        }

        len = SSL_read(ssl, buffer, sizeof(buffer));
        if (len > 0) {
            printf("Server response: %.*s\n", len, buffer);
        } else {
            int error = SSL_get_error(ssl, len);
            if (error == SSL_ERROR_ZERO_RETURN) {
                printf("Server disconnected.\n");
            } else {
                handle_error("DTLS read error.");
            }
            break;
        }
    }

    // Cleanup and close the connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);

    // Cleanup the SSL context
    SSL_CTX_free(ctx);
}

int main() {
    dtls_client_echo();
    return 0;
}
