#include "packet.h"
#include "checksum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

static uint16_t packet_get16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static void make_packet_aad(const uint8_t *packet, size_t header_len,
                            size_t ip_header_len, uint8_t *aad)
{
    memcpy(aad, packet, header_len);
    aad[1] = 0;
    memset(aad + 2, 0, 2);
    aad[8] = 0;
    memset(aad + 10, 0, 2);
    memset(aad + ip_header_len + 16, 0, 2);
}

int tcp_payload_bounds(const uint8_t *packet, size_t packet_len,
                       size_t *payload_offset, size_t *payload_len)
{
    size_t ip_header_len, tcp_header_len, total_len;

    if (!packet || !payload_offset || !payload_len || packet_len < 40) return 0;
    if ((packet[0] >> 4) != 4 || packet[9] != IPPROTO_TCP) return 0;

    ip_header_len = (size_t)(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || ip_header_len > packet_len) return 0;
    if (packet_get16(packet + 6) & 0x3FFF) return 0;

    total_len = packet_get16(packet + 2);
    if (total_len < ip_header_len + 20 || total_len > packet_len) return 0;

    tcp_header_len = (size_t)(packet[ip_header_len + 12] >> 4) * 4;
    if (tcp_header_len < 20 || ip_header_len + tcp_header_len > total_len) return 0;

    *payload_offset = ip_header_len + tcp_header_len;
    *payload_len = total_len - *payload_offset;
    return 1;
}

int transform_tcp_payload(uint8_t *packet, size_t *packet_len, size_t capacity,
                          SessionState *session, int encrypt)
{
    unsigned char tag[GCM_TAG_LEN];
    unsigned char *scratch = NULL;
    unsigned char *aad = NULL;
    size_t payload_offset, payload_len, new_len, ip_header_len;
    int result;

    if (!packet || !packet_len || !session ||
        !tcp_payload_bounds(packet, *packet_len, &payload_offset, &payload_len)) return 0;
    ip_header_len = (size_t)(packet[0] & 0x0F) * 4;
    aad = malloc(payload_offset);
    if (!aad) return 0;
    make_packet_aad(packet, payload_offset, ip_header_len, aad);

    if (encrypt) {
        if (payload_len == 0 || payload_len > 65535 - GCM_TAG_LEN ||
            *packet_len + GCM_TAG_LEN > capacity) goto fail;
        scratch = malloc(payload_len);
        if (!scratch) goto fail;
        memcpy(scratch, packet + payload_offset, payload_len);
        result = aes_gcm_encrypt_payload(session, aad, (int)payload_offset,
                                          scratch, (int)payload_len,
                                          packet + payload_offset, tag);
        free(scratch);
        scratch = NULL;
        if (!result) goto fail;
        memcpy(packet + payload_offset + payload_len, tag, GCM_TAG_LEN);
        new_len = *packet_len + GCM_TAG_LEN;
    } else {
        if (payload_len < GCM_TAG_LEN) goto fail;
        scratch = malloc(payload_len - GCM_TAG_LEN);
        if (!scratch) goto fail;
        result = aes_gcm_decrypt_payload(session, aad, (int)payload_offset,
                                          packet + payload_offset,
                                          (int)(payload_len - GCM_TAG_LEN),
                                          packet + payload_offset + payload_len - GCM_TAG_LEN,
                                          scratch);
        if (result < 0) {
            goto fail;
        }
        memcpy(packet + payload_offset, scratch, (size_t)result);
        free(scratch);
        scratch = NULL;
        new_len = *packet_len - GCM_TAG_LEN;
    }

    if (checksum_fix_packet(packet, new_len) != CHECKSUM_OK) goto fail;
    *packet_len = new_len;
    free(aad);
    return 1;

fail:
    free(scratch);
    free(aad);
    return 0;
}

void parse_packet(unsigned char *buffer, int buflen) {
    if (!buffer || buflen < (int)sizeof(struct ethhdr)) return;
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        printf("Ethernet protocol is not IPv4\n");
        return; 
    }

    if (buflen < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;

    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    int ip_header_len = ip->ihl * 4;

    if (ip_header_len < 20 || buflen < (int)(sizeof(struct ethhdr) + ip_header_len)) return;

    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    if (ntohs(ip->tot_len) < ip_header_len + 20 ||
        buflen < (int)(sizeof(struct ethhdr) + ntohs(ip->tot_len))) return;
    unsigned char *tcp = buffer + sizeof(struct ethhdr) + ip_header_len;
    int tcp_header_len = (tcp[12] >> 4) * 4;

    if (tcp_header_len < 20 || ntohs(ip->tot_len) < ip_header_len + tcp_header_len) return;

    int total_ip_len = ntohs(ip->tot_len);
    int payload_len = total_ip_len - (ip_header_len + tcp_header_len);

    if (payload_len > 0) {
        printf("TCP Payload found! Length: %d bytes\n", payload_len);
    }
}