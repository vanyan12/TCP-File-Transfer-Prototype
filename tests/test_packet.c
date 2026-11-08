#include "checksum.h"
#include "packet.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const unsigned char message[] = "secure inline payload";
    unsigned char packet[256] = { 0 };
    unsigned char tampered[256];
    unsigned char encrypted[256];
    unsigned char original[256];
    unsigned char tx_key[AES_KEY_LEN], rx_key[AES_KEY_LEN];
    unsigned char tx_salt[NONCE_SALT_LEN] = { 1, 2, 3, 4 };
    unsigned char rx_salt[NONCE_SALT_LEN] = { 5, 6, 7, 8 };
    SessionState sender, receiver;
    size_t packet_len = 40 + sizeof message - 1;

    packet[0] = 0x45;
    packet[2] = (unsigned char)(packet_len >> 8);
    packet[3] = (unsigned char)packet_len;
    packet[8] = 64;
    packet[9] = IPPROTO_TCP;
    packet[12] = 10;
    packet[15] = 1;
    packet[16] = 10;
    packet[19] = 2;
    packet[20] = 0x12;
    packet[21] = 0x34;
    packet[22] = 0x56;
    packet[23] = 0x78;
    packet[32] = 0x50;
    memcpy(packet + 40, message, sizeof message - 1);
    assert(checksum_fix_packet(packet, packet_len) == CHECKSUM_OK);
    memcpy(original, packet, packet_len);

    for (size_t i = 0; i < sizeof tx_key; i++) {
        tx_key[i] = (unsigned char)i;
        rx_key[i] = (unsigned char)(0xA0 + i);
    }
    crypto_session_init(&sender);
    crypto_session_init(&receiver);
    crypto_session_set_keys(&sender, tx_key, tx_salt, rx_key, rx_salt);
    crypto_session_set_keys(&receiver, rx_key, rx_salt, tx_key, tx_salt);

    assert(transform_tcp_payload(packet, &packet_len, sizeof packet, &sender, 1));
    assert(packet_len == 40 + sizeof message - 1 + GCM_TAG_LEN);
    assert(checksum_verify_packet(packet, packet_len) == CHECKSUM_OK);
    memcpy(encrypted, packet, packet_len);
    memcpy(tampered, packet, packet_len);
    tampered[40] ^= 1;
    {
        SessionState tamper_receiver;
        crypto_session_init(&tamper_receiver);
        crypto_session_set_keys(&tamper_receiver, rx_key, rx_salt, tx_key, tx_salt);
        assert(!transform_tcp_payload(tampered, &packet_len, sizeof tampered, &tamper_receiver, 0));
        crypto_session_destroy(&tamper_receiver);
    }
    assert(transform_tcp_payload(packet, &packet_len, sizeof packet, &receiver, 0));
    assert(packet_len == 40 + sizeof message - 1);
    assert(memcmp(packet, original, packet_len) == 0);
    assert(checksum_verify_packet(packet, packet_len) == CHECKSUM_OK);

    packet_len = 40 + sizeof message - 1 + GCM_TAG_LEN;
    memcpy(packet, encrypted, packet_len);
    assert(!transform_tcp_payload(packet, &packet_len, sizeof packet, &receiver, 0));

    crypto_session_destroy(&sender);
    crypto_session_destroy(&receiver);
    puts("packet crypto round-trip: ok");
    return 0;
}