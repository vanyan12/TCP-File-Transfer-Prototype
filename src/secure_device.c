#define _GNU_SOURCE
#define OPENSSL_SUPPRESS_DEPRECATED

#include "crypto.h"
#include "packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define HANDSHAKE_NONCE_LEN 32
#define HANDSHAKE_MAC_LEN 32
#define PACKET_CAPACITY 65535

static volatile sig_atomic_t running = 1;

static void stop_device(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static int write_all(int fd, const void *data, size_t length)
{
    const unsigned char *p = data;
    while (length > 0) {
        ssize_t written = send(fd, p, length, MSG_NOSIGNAL);
        if (written <= 0) return 0;
        p += written;
        length -= (size_t)written;
    }
    return 1;
}

static int read_all(int fd, void *data, size_t length)
{
    unsigned char *p = data;
    while (length > 0) {
        ssize_t received = recv(fd, p, length, 0);
        if (received <= 0) return 0;
        p += received;
        length -= (size_t)received;
    }
    return 1;
}

static int handshake_mac(const char *label, const unsigned char *body, size_t body_len,
                         const char *psk, unsigned char mac[HANDSHAKE_MAC_LEN])
{
    unsigned char input[512];
    size_t label_len = strlen(label);
    unsigned int mac_len = HANDSHAKE_MAC_LEN;
    if (label_len + body_len > sizeof input) return 0;
    memcpy(input, label, label_len);
    memcpy(input + label_len, body, body_len);
    return HMAC(EVP_sha256(), psk, (int)strlen(psk), input, label_len + body_len,
                mac, &mac_len) != NULL;
}

static int verify_handshake_mac(const char *label, const unsigned char *body, size_t body_len,
                                const unsigned char received[HANDSHAKE_MAC_LEN], const char *psk)
{
    unsigned char expected[HANDSHAKE_MAC_LEN];
    int ok = handshake_mac(label, body, body_len, psk, expected) &&
             CRYPTO_memcmp(expected, received, HANDSHAKE_MAC_LEN) == 0;
    OPENSSL_cleanse(expected, sizeof expected);
    return ok;
}

static int establish_session(int control_fd, int initiator, SessionState *session)
{
    DH *dh = NULL;
    unsigned char local_pub[DH_PUB_LEN], peer_pub[DH_PUB_LEN];
    unsigned char local_nonce[HANDSHAKE_NONCE_LEN], peer_nonce[HANDSHAKE_NONCE_LEN];
    unsigned char initiator_message[DH_PUB_LEN + HANDSHAKE_NONCE_LEN + HANDSHAKE_MAC_LEN];
    unsigned char responder_message[DH_PUB_LEN + HANDSHAKE_NONCE_LEN + HANDSHAKE_MAC_LEN];
    unsigned char salt[2 * HANDSHAKE_NONCE_LEN], transcript[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash;
    const char *psk = getenv("SECURE_DEVICE_PSK");
    int ok = 0;

    if (!psk || !*psk) goto out;
    dh = init_dh_handshake();
    if (!dh || RAND_bytes(local_nonce, sizeof local_nonce) != 1 ||
        get_dh_public_key_bytes(dh, local_pub, sizeof local_pub) != DH_PUB_LEN) goto out;

    if (initiator) {
        memcpy(initiator_message, local_pub, DH_PUB_LEN);
        memcpy(initiator_message + DH_PUB_LEN, local_nonce, HANDSHAKE_NONCE_LEN);
        if (!handshake_mac("device1", initiator_message, DH_PUB_LEN + HANDSHAKE_NONCE_LEN,
                           psk, initiator_message + DH_PUB_LEN + HANDSHAKE_NONCE_LEN)) goto out;
        if (!write_all(control_fd, initiator_message, sizeof initiator_message) ||
            !read_all(control_fd, responder_message, sizeof responder_message)) goto out;
        if (!verify_handshake_mac("device2", responder_message, DH_PUB_LEN + HANDSHAKE_NONCE_LEN,
                                  responder_message + DH_PUB_LEN + HANDSHAKE_NONCE_LEN, psk)) goto out;
        memcpy(peer_pub, responder_message, DH_PUB_LEN);
        memcpy(peer_nonce, responder_message + DH_PUB_LEN, HANDSHAKE_NONCE_LEN);
    } else {
        if (!read_all(control_fd, initiator_message, sizeof initiator_message)) goto out;
        if (!verify_handshake_mac("device1", initiator_message, DH_PUB_LEN + HANDSHAKE_NONCE_LEN,
                      initiator_message + DH_PUB_LEN + HANDSHAKE_NONCE_LEN, psk)) goto out;
        memcpy(peer_pub, initiator_message, DH_PUB_LEN);
        memcpy(peer_nonce, initiator_message + DH_PUB_LEN, HANDSHAKE_NONCE_LEN);
        memcpy(responder_message, local_pub, DH_PUB_LEN);
        memcpy(responder_message + DH_PUB_LEN, local_nonce, HANDSHAKE_NONCE_LEN);
        if (!handshake_mac("device2", responder_message, DH_PUB_LEN + HANDSHAKE_NONCE_LEN,
                   psk, responder_message + DH_PUB_LEN + HANDSHAKE_NONCE_LEN)) goto out;
        if (!write_all(control_fd, responder_message, sizeof responder_message)) goto out;
    }

    SHA256_Init(&hash);
    SHA256_Update(&hash, initiator_message, sizeof initiator_message);
    SHA256_Update(&hash, responder_message, sizeof responder_message);
    SHA256_Final(transcript, &hash);

    if (initiator) {
        memcpy(salt, local_nonce, HANDSHAKE_NONCE_LEN);
        memcpy(salt + HANDSHAKE_NONCE_LEN, peer_nonce, HANDSHAKE_NONCE_LEN);
    } else {
        memcpy(salt, peer_nonce, HANDSHAKE_NONCE_LEN);
        memcpy(salt + HANDSHAKE_NONCE_LEN, local_nonce, HANDSHAKE_NONCE_LEN);
    }

    ok = compute_shared_session_key(dh, peer_pub, sizeof peer_pub,
                                    salt, sizeof salt, transcript, sizeof transcript,
                                    initiator, session);
out:
    if (dh) DH_free(dh);
    OPENSSL_cleanse(local_pub, sizeof local_pub);
    OPENSSL_cleanse(peer_pub, sizeof peer_pub);
    OPENSSL_cleanse(local_nonce, sizeof local_nonce);
    OPENSSL_cleanse(peer_nonce, sizeof peer_nonce);
    OPENSSL_cleanse(initiator_message, sizeof initiator_message);
    OPENSSL_cleanse(responder_message, sizeof responder_message);
    OPENSSL_cleanse(salt, sizeof salt);
    OPENSSL_cleanse(transcript, sizeof transcript);
    return ok;
}

static int connect_control(const char *address, uint16_t port)
{
    struct sockaddr_in peer = { 0 };
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &peer.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&peer, sizeof peer) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int accept_control(uint16_t port)
{
    struct sockaddr_in address = { 0 };
    int server = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    int fd;
    if (server < 0) return -1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server, (struct sockaddr *)&address, sizeof address) < 0 ||
        listen(server, 1) < 0) {
        close(server);
        return -1;
    }
    fd = accept(server, NULL, NULL);
    close(server);
    return fd;
}

static int queue_callback(struct nfq_q_handle *queue, struct nfgenmsg *message,
                          struct nfq_data *packet, void *context)
{
    SessionState *session = context;
    unsigned char modified[PACKET_CAPACITY];
    unsigned char *payload;
    size_t payload_offset, payload_length;
    size_t packet_len;
    uint32_t id = 0;
    int encrypt = session->transform_encrypt;
    int length;

    (void)message;
    if (nfq_get_msg_packet_hdr(packet)) id = ntohl(nfq_get_msg_packet_hdr(packet)->packet_id);
    length = nfq_get_payload(packet, &payload);
    if (length < 0 || (size_t)length > sizeof modified) return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
    if (!tcp_payload_bounds(payload, (size_t)length, &payload_offset, &payload_length) ||
        payload_length == 0)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
    (void)payload_offset;
    memcpy(modified, payload, (size_t)length);
    packet_len = (size_t)length;

    if (!transform_tcp_payload(modified, &packet_len, sizeof modified, session, encrypt))
        return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(queue, id, NF_ACCEPT, (uint32_t)packet_len, modified);
}

static int run_queue(SessionState *session, uint16_t queue_number)
{
    struct nfq_handle *handle;
    struct nfq_q_handle *queue;
    int fd, flags, status;
    unsigned char buffer[PACKET_CAPACITY];

    handle = nfq_open();
    if (!handle) return 0;
    nfq_unbind_pf(handle, AF_INET);
    if (nfq_bind_pf(handle, AF_INET) < 0) goto fail_handle;
    queue = nfq_create_queue(handle, queue_number, &queue_callback, session);
    if (!queue) goto fail_handle;
    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, PACKET_CAPACITY) < 0) goto fail_queue;

    fd = nfq_fd(handle);
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    while (running) {
        status = recv(fd, (char *)buffer, sizeof buffer, 0);
        if (status < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(10000);
            continue;
        }
        if (status < 0) break;
        if (nfq_handle_packet(handle, (char *)buffer, status) < 0) break;
    }
    nfq_destroy_queue(queue);
    nfq_close(handle);
    return 1;
fail_queue:
    nfq_destroy_queue(queue);
fail_handle:
    nfq_close(handle);
    return 0;
}

int main(int argc, char **argv)
{
    int initiator, control_fd;
    uint16_t port, queue_number;
    SessionState session;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <device1|device2> <peer-ip-or-> <control-port> <queue>\n", argv[0]);
        return EXIT_FAILURE;
    }
    initiator = strcmp(argv[1], "device1") == 0;
    if (!initiator && strcmp(argv[1], "device2") != 0) return EXIT_FAILURE;
    port = (uint16_t)strtoul(argv[3], NULL, 10);
    queue_number = (uint16_t)strtoul(argv[4], NULL, 10);

    signal(SIGINT, stop_device);
    signal(SIGTERM, stop_device);
    crypto_session_init(&session);
    control_fd = initiator ? connect_control(argv[2], port) : accept_control(port);
    if (control_fd < 0 || !establish_session(control_fd, initiator, &session)) {
        fprintf(stderr, "secure session handshake failed\n");
        if (control_fd >= 0) close(control_fd);
        crypto_session_destroy(&session);
        return EXIT_FAILURE;
    }
    close(control_fd);

    session.transform_encrypt = initiator;
    fprintf(stderr, "secure session established; waiting for NFQUEUE %u\n", queue_number);
    if (!run_queue(&session, queue_number)) fprintf(stderr, "NFQUEUE setup failed\n");
    crypto_session_destroy(&session);
    return EXIT_SUCCESS;
}