#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP   "192.168.126.124"  // Change to your DICOM server IP
#define SERVER_PORT 4242               // Standard DICOM port
#define BUFFER_SIZE 1024

const unsigned char a_associate_rq[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0xe1,  // PDU Type (0x01 = A-ASSOCIATE-RQ), Length (0x00E1 = 225 bytes)
    0x00, 0x01,  // Protocol version
    0x00, 0x00,  // Reserved
    'M', 'y', 'O', 'r', 't', 'h', 'a', 'n', 'c', // Called AE Title
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', // Padding
    'M', 'O', 'D', 'A', 'L', 'I', 'T', 'Y', // Calling AE Title
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', // Padding
    0x00, 0x00, 0x00, 0x00,  // Reserved
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //0x00, 0x00, 0x00, 0x00,

    0x10, 0x00, 0x00, 0x15,  // Application Context Item (0x10), Length (0x15)
    '1', '.', '2', '.', '8', '4', '0', '.', '1', '0', '0', '0', '8', '.', '3', '.', '1', '.', '1', '.', '1',

    0x20, 0x00, 0x00, 0x3e,  // Presentation Context Item (0x20), Length (0x3E)
    0x01, 0x00,  // Presentation Context ID
    0x00, 0x00,  // Reserved
    0x30, 0x00, 0x00, 0x1c,  // Abstract Syntax (0x30), Length (0x1C)
    '1', '.', '2', '.', '8', '4', '0', '.', '1', '0', '0', '0', '8', '.', '5', '.', '1', '.', '4', '.', '1', '.', '1', '.', '1', '2', '.', '1',

    0x40, 0x00, 0x00, 0x16,  // Transfer Syntax (0x40), Length (0x16)
    '1', '.', '2', '.', '8', '4', '0', '.', '1', '0', '0', '0', '8', '.', '1', '.', '2', '.', '4', '.', '5', '0',

    0x50, 0x00, 0x00, 0x3e,  // Presentation Context Item
    0x51, 0x00, 0x00, 0x04,  // User Info Item
    0x00, 0x00, 0x3f, 0xfe,  // Max PDU Length
    0x52, 0x00, 0x00, 0x20,  // Implementation Class UID
    '1', '.', '2', '.', '8', '2', '6', '.', '0', '.', '1', '.', '3', '6', '8', '0', '0', '4', '3', '.', '9', '.', '3', '8', '1', '1', '.', '2', '.', '1', '.', '0',

    0x55, 0x00, 0x00, 0x0e,  // Implementation Version Name
    'P', 'Y', 'N', 'E', 'T', 'D', 'I', 'C', 'O', 'M', '_', '2', '1', '0'
};

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_sent, bytes_received;

    // 1. Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 2. Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 3. Connect to the DICOM server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[+] Connected to DICOM server %s:%d\n", SERVER_IP, SERVER_PORT);

    // 4. Send A-ASSOCIATE RQ (Association Request)
    printf("Expected A-ASSOCIATE-RQ size: %lu bytes\n", sizeof(a_associate_rq));

    bytes_sent = send(sockfd, a_associate_rq, sizeof(a_associate_rq), 0);
    if (bytes_sent < 0) {
        perror("[-] Failed to send A-ASSOCIATE RQ");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[+] A-ASSOCIATE RQ sent (%ld bytes)\n", bytes_sent);

    // 5. Wait for A-ASSOCIATE AC (Association Accept)
    bytes_received = recv(sockfd, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("[-] Failed to receive A-ASSOCIATE AC");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 6. Check if it's an A-ASSOCIATE AC
    if (buffer[0] == 0x02) {
        printf("[+] Received A-ASSOCIATE AC (%ld bytes)\n", bytes_received);
    } else {
        printf("[-] Unexpected response received\n");
    }

    // 7. Close the connection
    close(sockfd);
    printf("[+] Connection closed\n");

    return 0;
}