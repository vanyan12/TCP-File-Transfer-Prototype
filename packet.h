#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

int tcp_payload_bounds(const uint8_t *packet, size_t packet_len,
					   size_t *payload_offset, size_t *payload_len);

int transform_tcp_payload(uint8_t *packet, size_t *packet_len, size_t capacity,
						  SessionState *session, int encrypt);

void parse_packet(unsigned char *buffer, int buflen);

#endif