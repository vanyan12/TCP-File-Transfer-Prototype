#ifndef CHECKSUM_H
#define CHECKSUM_H
/*
 * checksum.h - IPv4 / TCP checksum calculation and packet repair.
 *
 * After the TCP payload is encrypted (+16 byte tag) or decrypted (-16 byte tag) the packet length changes, so
 * three header fields are wrong and must be rebuilt before the packet is forwarded:
 *   1. IP total length        (bytes 2-3 of the IP header)
 *   2. IP header checksum     (bytes 10-11)
 *   3. TCP checksum           (TCP header bytes 16-17, covers pseudo header + TCP header + payload)
 *
 * All functions work on a raw IPv4 packet (starting at the IP header, as delivered by NFQUEUE), are
 * independent of CPU byte order and alignment, and never write outside [pkt, pkt + pkt_len).
 */
#include <stddef.h>
#include <stdint.h>

#define CHECKSUM_OK            0
#define CHECKSUM_E_MALFORMED  -1   /* not IPv4/TCP, fragment, truncated, bad header lengths */
#define CHECKSUM_E_IP         -2   /* IP header checksum wrong */
#define CHECKSUM_E_TCP        -3   /* TCP checksum wrong */

/* RFC 1071 Internet checksum of an arbitrary buffer: one's complement of the one's complement sum of its
 * 16-bit big-endian words (an odd last byte is padded with a zero). A buffer that already contains its own
 * correct checksum gives 0. */
uint16_t checksum_rfc1071(const void *data, size_t len);

/* Checksum of the IP header at `ip` (header length from its IHL field), computed as if the header's checksum field
 * were zero. Precondition: IHL >= 5 and IHL*4 readable bytes (checksum_fix_packet / checksum_verify_packet check
 * this for you; call this low-level function directly only on validated headers). */
uint16_t checksum_ip_header(const uint8_t *ip);

/* Checksum of the TCP segment at `tcp` (header + payload, `tcp_len` bytes) with the IPv4 pseudo header taken from
 * `ip` (source address, destination address, protocol, TCP length). The segment's own checksum field is treated
 * as zero. Precondition: tcp_len >= 20 and `ip` has at least 20 readable bytes (same note as above). */
uint16_t checksum_tcp_segment(const uint8_t *ip, const uint8_t *tcp, size_t tcp_len);

/*
 * Repair a packet after its payload was changed.
 * pkt_len is the NEW size of the whole packet; it becomes the IP total length. Then the IP header checksum and the
 * TCP checksum are recomputed in place. Returns CHECKSUM_OK or CHECKSUM_E_MALFORMED (packet left untouched).
 */
int checksum_fix_packet(uint8_t *pkt, size_t pkt_len);

/* Verify an existing packet (IP total length must fit in pkt_len; bytes beyond it, e.g. padding, are ignored).
 * Returns CHECKSUM_OK, CHECKSUM_E_MALFORMED, CHECKSUM_E_IP or CHECKSUM_E_TCP. */
int checksum_verify_packet(const uint8_t *pkt, size_t pkt_len);

#endif