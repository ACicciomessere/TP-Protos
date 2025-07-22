#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

// Mock POP3 server for testing the sniffer
void* mock_pop3_server(void* arg) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("mock server socket");
        return NULL;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(110); // POP3 port
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("mock server bind");
        close(server_sock);
        return NULL;
    }
    
    if (listen(server_sock, 1) < 0) {
        perror("mock server listen");
        close(server_sock);
        return NULL;
    }
    
    printf("Mock POP3 server listening on port 110\n");
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
    
    if (client_sock < 0) {
        perror("mock server accept");
        close(server_sock);
        return NULL;
    }
    
    printf("Mock POP3 server: client connected\n");
    
    // Send POP3 greeting
    char greeting[] = "+OK Mock POP3 server ready\r\n";
    send(client_sock, greeting, strlen(greeting), 0);
    
    // Keep connection open for a while
    sleep(5);
    
    close(client_sock);
    close(server_sock);
    return NULL;
}

int main(void) {
    printf("POP3 Sniffer Test - Testing with mock POP3 server\n");
    printf("This test will:\n");
    printf("1. Start a mock POP3 server on port 110\n");
    printf("2. Connect through SOCKS5 proxy\n");
    printf("3. Send POP3 credentials that should be captured\n");
    printf("4. Check if pop3_credentials.log is created\n\n");
    
    // Start mock POP3 server in background
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, mock_pop3_server, NULL);
    
    sleep(1); // Give server time to start
    
    // Connect to SOCKS5
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1080);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect to SOCKS5");
        close(sock);
        return 1;
    }
    
    printf("Connected to SOCKS5 server\n");
    
    // SOCKS5 handshake - no authentication required
    char handshake[] = {0x05, 0x01, 0x00}; // Version 5, 1 method, no auth
    if (send(sock, handshake, 3, 0) != 3) {
        perror("send handshake");
        close(sock);
        return 1;
    }
    
    char response[2];
    if (recv(sock, response, 2, 0) != 2) {
        perror("recv handshake response");
        close(sock);
        return 1;
    }
    
    if (response[1] != 0x00) {
        printf("Authentication required (unexpected)\n");
        close(sock);
        return 1;
    }
    
    printf("No authentication required ✓\n");
    
    // Send SOCKS5 request to connect to our mock POP3 server
    char request[] = {0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x6e}; // Connect to 127.0.0.1:110
    if (send(sock, request, 10, 0) != 10) {
        perror("send connect request");
        close(sock);
        return 1;
    }
    
    // SOCKS5 reply: 3 bytes header + 1 byte ATYP + 4 bytes IP + 2 bytes port = 10 bytes total
    char reply[10];
    int total_received = 0;
    int timeout_count = 0;
    
    while (total_received < 10 && timeout_count < 10) {
        int received = recv(sock, reply + total_received, 10 - total_received, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000); // 100ms
                timeout_count++;
                continue;
            }
            perror("recv connect reply");
            close(sock);
            return 1;
        } else if (received == 0) {
            printf("Connection closed by server\n");
            close(sock);
            return 1;
        } else {
            total_received += received;
        }
    }
    
    if (total_received != 10) {
        printf("Incomplete reply: received %d/10 bytes\n", total_received);
        close(sock);
        return 1;
    }
    
    if (reply[1] == 0x00) {
        printf("Connected through SOCKS5 to mock POP3 server ✓\n");
        
        // Receive greeting from mock server
        char buffer[1024];
        int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            printf("Received from mock server: %s", buffer);
        }
        
        // Send POP3-like data that should trigger the sniffer
        char pop3_data[] = "USER testuser\r\nPASS testpass\r\n";
        if (send(sock, pop3_data, strlen(pop3_data), 0) != strlen(pop3_data)) {
            perror("send POP3 data");
        } else {
            printf("Sent POP3 data: %s", pop3_data);
        }
        
        sleep(2); // Give time for processing
        
        // Check if credentials were captured
        if (access("pop3_credentials.log", F_OK) == 0) {
            printf("\n✓ SUCCESS: pop3_credentials.log was created!\n");
            printf("Contents:\n");
            system("cat pop3_credentials.log");
        } else {
            printf("\n✗ FAILED: pop3_credentials.log was not created\n");
        }
    } else {
        printf("SOCKS5 connection failed with code: %d\n", reply[1]);
    }
    
    close(sock);
    pthread_join(server_thread, NULL);
    return 0;
}
