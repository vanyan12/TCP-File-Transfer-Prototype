#ifndef CRYPTO_H
#define CRYPTO_H

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/dh.h>

#define AES_KEY_LEN       32
#define GCM_IV_LEN        12
#define GCM_TAG_LEN       16
#define NONCE_SALT_LEN    4
#define DH_PUB_LEN        256
#define REPLAY_WINDOW     256
#define REPLAY_MEMORY     1024
#define REKEY_THRESHOLD   (1ULL << 31)
#define NONCE_HARD_LIMIT  (1ULL << 32)

typedef struct {
    unsigned char tx_key[AES_KEY_LEN];
    unsigned char rx_key[AES_KEY_LEN];
    unsigned char tx_salt[NONCE_SALT_LEN];
    unsigned char rx_salt[NONCE_SALT_LEN];

    _Atomic uint64_t nonce_counter;

    pthread_mutex_t rx_lock;
    _Atomic uint64_t rx_next;
    uint64_t rx_seen[REPLAY_MEMORY];
    int transform_encrypt;
} SessionState;

void crypto_session_init(SessionState *st);
void crypto_session_destroy(SessionState *st);
void crypto_session_set_keys(SessionState *st,
                             const unsigned char tx_key[AES_KEY_LEN], const unsigned char tx_salt[NONCE_SALT_LEN],
                             const unsigned char rx_key[AES_KEY_LEN], const unsigned char rx_salt[NONCE_SALT_LEN]);
int  crypto_session_needs_rekey(SessionState *st);
int  crypto_next_iv(SessionState *st, unsigned char iv[GCM_IV_LEN]);

int aes_gcm_encrypt_payload(SessionState *state,
                            const unsigned char *aad, int aad_len,
                            const unsigned char *plaintext, int plaintext_len,
                            unsigned char *ciphertext, unsigned char *tag);

int aes_gcm_decrypt_payload(SessionState *state,
                            const unsigned char *aad, int aad_len,
                            const unsigned char *ciphertext, int ciphertext_len,
                            const unsigned char *tag,
                            unsigned char *plaintext);

DH  *init_dh_handshake(void);
int  get_dh_public_key_bytes(DH *dh, unsigned char *buf, int buf_len);
int  compute_shared_session_key(DH *dh, const unsigned char *peer_pub_bytes, int peer_pub_len,
                               const unsigned char *salt, size_t salt_len,
                               const unsigned char *transcript, size_t transcript_len,
                               int is_initiator, SessionState *state);

int crypto_hkdf_sha256(const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len, unsigned char *out, size_t out_len);

#endif