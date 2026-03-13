
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/* Minimal TCP header (20 bytes, no options) */
struct tcphdr_min {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res;  /* data offset (4 bits) + reserved (4 bits) */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

/* Pseudo-header for TCP checksum over IPv4 */
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

static uint16_t checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *p = data;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)p;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int main()
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        perror("socket(SOCK_RAW)");
        return 1;
    }

    /* We build the IP header ourselves (IPPROTO_RAW implies IP_HDRINCL) */
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    uint16_t src_port = htons(44444);
    uint16_t dst_port = htons(55555);

    for (int i = 0; i < 2000; i++) {
        char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr_min)] = {0};
        struct iphdr *ip       = (struct iphdr *)pkt;
        struct tcphdr_min *tcp = (struct tcphdr_min *)(pkt + sizeof(struct iphdr));

        /* IP header */
        ip->ihl     = 5;
        ip->version = 4;
        ip->tot_len = htons(sizeof(pkt));
        ip->id      = htons(54321 + i);
        ip->ttl     = 64;
        ip->protocol = 6;  /* IPPROTO_TCP */
        ip->saddr   = htonl(INADDR_LOOPBACK);
        ip->daddr   = htonl(INADDR_LOOPBACK);
        ip->check   = 0;
        ip->check   = checksum(ip, sizeof(struct iphdr));

        /* TCP header */
        tcp->src_port = src_port;
        tcp->dst_port = dst_port;
        tcp->seq      = htonl(1000 + i);
        tcp->ack_seq  = 0;
        tcp->doff_res = (5 << 4);  /* data offset = 5 words (20 bytes) */
        tcp->flags    = 0x02;      /* SYN */
        tcp->window   = htons(65535);
        tcp->checksum = 0;
        tcp->urg_ptr  = 0;

        /* TCP checksum (with pseudo-header) */
        struct pseudo_hdr ph = {
            .src     = ip->saddr,
            .dst     = ip->daddr,
            .zero    = 0,
            .proto   = 6,
            .tcp_len = htons(sizeof(struct tcphdr_min)),
        };
        char csum_buf[sizeof(ph) + sizeof(struct tcphdr_min)];
        memcpy(csum_buf, &ph, sizeof(ph));
        memcpy(csum_buf + sizeof(ph), tcp, sizeof(struct tcphdr_min));
        tcp->checksum = checksum(csum_buf, sizeof(csum_buf));

        ssize_t ret = sendto(sock, pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&dst_addr, sizeof(dst_addr));
        if (ret == -1) {
            perror("sendto");
            close(sock);
            return 1;
        }
    }

    /* Stay alive so monitor can inspect stats */
    for (;;) pause();
    return 0;
}

