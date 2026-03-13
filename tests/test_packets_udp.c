// test_packets_udp.c
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(12345),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    char msg[] = "x";
    for (int i = 0; i < 2000; i++)
        sendto(sock, msg, 1, 0, (struct sockaddr*)&addr, sizeof(addr));

    sleep(999999);
    return 0;
}
