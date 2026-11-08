#include "checksum.h"

#include <string.h>

#define IP_MIN_HDR    20
#define TCP_MIN_HDR   20
#define IP_PROTO_TCP  6
#define IP_MAX_LEN    65535

/* ------------------------------------------------------------------------- */
/* One's complement arithmetic (RFC 1071)                                    */
/* ------------------------------------------------------------------------- */

static uint64_t sum_words(uint64_t sum, const uint8_t *d, size_t n)
{
    size_t i = 0;
    for (; i + 1 < n; i += 2) sum += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1) sum += (uint32_t)d[n - 1] << 8;
    return sum;
}

static uint16_t fold(uint64_t sum)
{
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)sum;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p)   { return (uint16_t)(((unsigned)p[0] << 8) | p[1]); }

uint16_t checksum_rfc1071(const void *data, size_t len)
{
    return (uint16_t)~fold(sum_words(0, (const uint8_t *)data, len));
}

uint16_t checksum_ip_header(const uint8_t *ip)
{
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
    uint64_t s = sum_words(0, ip, 10);
    s = sum_words(s, ip + 12, ihl - 12);
    return (uint16_t)~fold(s);
}

uint16_t checksum_tcp_segment(const uint8_t *ip, const uint8_t *tcp, size_t tcp_len)
{
    uint8_t ph[12];
    memcpy(ph, ip + 12, 8);
    ph[8] = 0;
    ph[9] = IP_PROTO_TCP;
    put16(ph + 10, (uint16_t)tcp_len);

    uint64_t s = sum_words(0, ph, sizeof ph);
    s = sum_words(s, tcp, 16);
    s = sum_words(s, tcp + 18, tcp_len - 18);
    return (uint16_t)~fold(s);
}

static int parse(const uint8_t *pkt, size_t pkt_len, int total_from_header, size_t *ihl_out, size_t *total_out)
{
    if (!pkt || pkt_len < IP_MIN_HDR + TCP_MIN_HDR || pkt_len > IP_MAX_LEN) return CHECKSUM_E_MALFORMED;
    if ((pkt[0] >> 4) != 4) return CHECKSUM_E_MALFORMED;
    size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < IP_MIN_HDR || ihl + TCP_MIN_HDR > pkt_len) return CHECKSUM_E_MALFORMED;
    if (pkt[9] != IP_PROTO_TCP) return CHECKSUM_E_MALFORMED;
    if (get16(pkt + 6) & 0x3FFF) return CHECKSUM_E_MALFORMED;

    size_t total = total_from_header ? get16(pkt + 2) : pkt_len;
    if (total > pkt_len || total < ihl + TCP_MIN_HDR) return CHECKSUM_E_MALFORMED;

    size_t doff = (size_t)(pkt[ihl + 12] >> 4) * 4;
    if (doff < TCP_MIN_HDR || ihl + doff > total) return CHECKSUM_E_MALFORMED;

    *ihl_out = ihl;
    *total_out = total;
    return CHECKSUM_OK;
}

int checksum_fix_packet(uint8_t *pkt, size_t pkt_len)
{
    size_t ihl, total;
    int r = parse(pkt, pkt_len, 0, &ihl, &total);
    if (r != CHECKSUM_OK) return r;

    put16(pkt + 2, (uint16_t)total);
    put16(pkt + 10, checksum_ip_header(pkt));
    put16(pkt + ihl + 16, checksum_tcp_segment(pkt, pkt + ihl, total - ihl));
    return CHECKSUM_OK;
}

int checksum_verify_packet(const uint8_t *pkt, size_t pkt_len)
{
    size_t ihl, total;
    int r = parse(pkt, pkt_len, 1, &ihl, &total);
    if (r != CHECKSUM_OK) return r;

    if (checksum_ip_header(pkt) != get16(pkt + 10)) return CHECKSUM_E_IP;
    if (checksum_tcp_segment(pkt, pkt + ihl, total - ihl) != get16(pkt + ihl + 16)) return CHECKSUM_E_TCP;
    return CHECKSUM_OK;
}