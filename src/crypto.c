#define OPENSSL_SUPPRESS_DEPRECATED
#include "crypto.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <string.h>

void crypto_session_init(SessionState *st)
{
    memset(st, 0, sizeof *st);
    atomic_init(&st->nonce_counter, 0);
    atomic_init(&st->rx_next, 0);
    pthread_mutex_init(&st->rx_lock, NULL);
}

void crypto_session_destroy(SessionState *st)
{
    OPENSSL_cleanse(st, offsetof(SessionState, nonce_counter));
    pthread_mutex_destroy(&st->rx_lock);
}

void crypto_session_set_keys(SessionState *st,
                             const unsigned char tx_key[AES_KEY_LEN], const unsigned char tx_salt[NONCE_SALT_LEN],
                             const unsigned char rx_key[AES_KEY_LEN], const unsigned char rx_salt[NONCE_SALT_LEN])
{
    memcpy(st->tx_key, tx_key, AES_KEY_LEN);
    memcpy(st->rx_key, rx_key, AES_KEY_LEN);
    memcpy(st->tx_salt, tx_salt, NONCE_SALT_LEN);
    memcpy(st->rx_salt, rx_salt, NONCE_SALT_LEN);
    atomic_store(&st->nonce_counter, 0);
    pthread_mutex_lock(&st->rx_lock);
    atomic_store(&st->rx_next, 0);
    memset(st->rx_seen, 0, sizeof st->rx_seen);
    pthread_mutex_unlock(&st->rx_lock);
}

int crypto_session_needs_rekey(SessionState *st)
{
    return atomic_load(&st->nonce_counter) >= REKEY_THRESHOLD || atomic_load(&st->rx_next) >= REKEY_THRESHOLD;
}

static void put_be64(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (56 - 8 * i));
}

static void make_iv(unsigned char iv[GCM_IV_LEN], const unsigned char salt[NONCE_SALT_LEN], uint64_t ctr)
{
    memcpy(iv, salt, NONCE_SALT_LEN);
    put_be64(iv + NONCE_SALT_LEN, ctr);
}

int crypto_next_iv(SessionState *st, unsigned char iv[GCM_IV_LEN])
{
    uint64_t n = atomic_fetch_add(&st->nonce_counter, 1);
    if (n >= NONCE_HARD_LIMIT) return 0;
    make_iv(iv, st->tx_salt, n);
    return 1;
}

int aes_gcm_encrypt_payload(SessionState *state,
                            const unsigned char *aad, int aad_len,
                            const unsigned char *plaintext, int plaintext_len,
                            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[GCM_IV_LEN];
    int len = 0, ok = 0;

    if (!state || !ciphertext || !tag || plaintext_len < 0 || aad_len < 0) return 0;
    if ((plaintext_len > 0 && !plaintext) || (aad_len > 0 && !aad)) return 0;
    if (!crypto_next_iv(state, iv)) return 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) return 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, state->tx_key, iv) != 1) goto out;
    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto out;
    if (plaintext_len > 0 && EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) goto out;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + plaintext_len, &len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) goto out;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int try_open(EVP_CIPHER_CTX *c, const unsigned char salt[NONCE_SALT_LEN], uint64_t ctr,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *ct, int ct_len, const unsigned char tag[GCM_TAG_LEN], unsigned char *pt)
{
    unsigned char iv[GCM_IV_LEN], tg[GCM_TAG_LEN];
    int l = 0, l2 = 0;
    make_iv(iv, salt, ctr);
    memcpy(tg, tag, GCM_TAG_LEN);
    if (EVP_DecryptInit_ex(c, NULL, NULL, NULL, iv) != 1) return 0;
    if (aad_len > 0 && EVP_DecryptUpdate(c, NULL, &l, aad, aad_len) != 1) return 0;
    if (ct_len > 0 && EVP_DecryptUpdate(c, pt, &l, ct, ct_len) != 1) return 0;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tg) != 1) return 0;
    return EVP_DecryptFinal_ex(c, pt + ct_len, &l2) > 0;
}

int aes_gcm_decrypt_payload(SessionState *state,
                            const unsigned char *aad, int aad_len,
                            const unsigned char *ciphertext, int ciphertext_len,
                            const unsigned char *tag,
                            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *c = NULL;
    int found = 0;
    uint64_t cand = 0;

    if (!state || !tag || !plaintext || ciphertext_len < 0 || aad_len < 0) return -1;
    if ((ciphertext_len > 0 && !ciphertext) || (aad_len > 0 && !aad)) return -1;

    if (!(c = EVP_CIPHER_CTX_new())) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, state->rx_key, NULL) != 1) {
        EVP_CIPHER_CTX_free(c);
        return -1;
    }

    pthread_mutex_lock(&state->rx_lock);
    uint64_t base = atomic_load(&state->rx_next);
    uint64_t lo = base > REPLAY_WINDOW ? base - REPLAY_WINDOW : 0;

    for (uint64_t i = 0; i < REPLAY_WINDOW && !found; i++) {
        cand = base + i;
        found = try_open(c, state->rx_salt, cand, aad, aad_len, ciphertext, ciphertext_len, tag, plaintext);
    }
    for (uint64_t k = base; k > lo && !found; k--) {
        cand = k - 1;
        if (state->rx_seen[cand % REPLAY_MEMORY] == cand + 1) continue;
        found = try_open(c, state->rx_salt, cand, aad, aad_len, ciphertext, ciphertext_len, tag, plaintext);
    }
    if (found) {
        state->rx_seen[cand % REPLAY_MEMORY] = cand + 1;
        if (cand >= base) atomic_store(&state->rx_next, cand + 1);
    }
    pthread_mutex_unlock(&state->rx_lock);
    EVP_CIPHER_CTX_free(c);

    if (!found) {
        OPENSSL_cleanse(plaintext, (size_t)ciphertext_len);
        return -1;
    }
    return ciphertext_len;
}

int crypto_hkdf_sha256(const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len, unsigned char *out, size_t out_len)
{
    unsigned char prk[32], t[32 + 128 + 1], blk[32];
    unsigned int pl = 32, l;
    size_t tl = 0, done = 0;
    static const unsigned char zero_salt[32] = { 0 };

    if (info_len > 128 || out_len > 255 * 32) return 0;
    if (!salt || salt_len == 0) { salt = zero_salt; salt_len = sizeof zero_salt; }
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &pl)) return 0;
    for (unsigned char i = 1; done < out_len; i++) {
        if (info_len) memcpy(t + tl, info, info_len);
        t[tl + info_len] = i;
        l = 32;
        if (!HMAC(EVP_sha256(), prk, 32, t, tl + info_len + 1, blk, &l)) { OPENSSL_cleanse(prk, 32); return 0; }
        size_t take = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, blk, take);
        memcpy(t, blk, 32);
        tl = 32;
        done += take;
    }
    OPENSSL_cleanse(prk, sizeof prk); OPENSSL_cleanse(blk, sizeof blk); OPENSSL_cleanse(t, sizeof t);
    return 1;
}

DH *init_dh_handshake(void)
{
    DH *dh = DH_new_by_nid(NID_modp_2048);
    if (!dh) return NULL;
    if (DH_generate_key(dh) != 1) { DH_free(dh); return NULL; }
    return dh;
}

int get_dh_public_key_bytes(DH *dh, unsigned char *buf, int buf_len)
{
    const BIGNUM *pub = NULL;
    if (!dh || !buf || buf_len < DH_PUB_LEN) return -1;
    DH_get0_key(dh, &pub, NULL);
    if (!pub) return -1;
    return BN_bn2binpad(pub, buf, DH_PUB_LEN) == DH_PUB_LEN ? DH_PUB_LEN : -1;
}

int compute_shared_session_key(DH *dh, const unsigned char *peer_pub_bytes, int peer_pub_len,
                               const unsigned char *salt, size_t salt_len,
                               const unsigned char *transcript, size_t transcript_len,
                               int is_initiator, SessionState *state)
{
    static const char label[] = "securechan v1 keys";
    unsigned char raw[DH_PUB_LEN], z[DH_PUB_LEN], info[sizeof label - 1 + 64], okm[2 * AES_KEY_LEN + 2 * NONCE_SALT_LEN];
    BIGNUM *peer = NULL;
    int ok = 0, codes = 0, n;

    if (!dh || !peer_pub_bytes || !state || peer_pub_len != DH_PUB_LEN || transcript_len > 64) return 0;
    if (!(peer = BN_bin2bn(peer_pub_bytes, peer_pub_len, NULL))) return 0;

    if (DH_check_pub_key(dh, peer, &codes) != 1 || codes != 0) goto out;

    n = DH_compute_key(raw, peer, dh);
    if (n <= 0 || n > DH_PUB_LEN) goto out;
    memset(z, 0, sizeof z);
    memcpy(z + (DH_PUB_LEN - n), raw, (size_t)n);

    memcpy(info, label, sizeof label - 1);
    if (transcript_len) memcpy(info + sizeof label - 1, transcript, transcript_len);
    if (!crypto_hkdf_sha256(salt, salt_len, z, sizeof z, info, sizeof label - 1 + transcript_len, okm, sizeof okm)) goto out;

    {
        const unsigned char *k_i2r = okm, *k_r2i = okm + 32, *s_i2r = okm + 64, *s_r2i = okm + 68;
        if (is_initiator) crypto_session_set_keys(state, k_i2r, s_i2r, k_r2i, s_r2i);
        else              crypto_session_set_keys(state, k_r2i, s_r2i, k_i2r, s_i2r);
    }
    ok = 1;
out:
    BN_free(peer);
    OPENSSL_cleanse(raw, sizeof raw); OPENSSL_cleanse(z, sizeof z); OPENSSL_cleanse(okm, sizeof okm);
    return ok;
}