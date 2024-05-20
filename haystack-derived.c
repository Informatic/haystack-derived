
#include <sha-256.h>
#include "haystack-derived.h"

// Quick and dirty X9.63-SHA256-KDF. Only supports output_len <8k
void x963_kdf_sha256(
    uint8_t *value, size_t value_len,
    uint8_t *sn, size_t sn_len,
    uint8_t *output, size_t output_len)
{
    size_t blocks = (output_len + 31) / 32;
    uint8_t temp[32];

    for (uint8_t b = 0; b < blocks; b++)
    {
        struct Sha_256 sha_state;
        uint8_t use_temp = (b == blocks - 1 && blocks * 32 != output_len);
        sha_256_init(&sha_state, use_temp ? temp : (output + b * 32));
        sha_256_write(&sha_state, value, value_len);
        uint8_t b_idx[4] = {0, 0, 0, b + 1};
        sha_256_write(&sha_state, b_idx, 4);
        sha_256_write(&sha_state, sn, sn_len);
        sha_256_close(&sha_state);

        if (use_temp)
        {
            memcpy(output + b * 32, temp, output_len - (blocks - 1) * 32);
        }
    }
}

// Reimplementation of:
// https://github.com/malmeloo/FindMy.py/blob/b97b094ccae0ca0c48a3900d1320a724d988d441/findmy/util/crypto.py#L56-L71
void derive_ps_key(uint8_t *privkey, size_t privkey_len, uint8_t *sk, size_t sk_len, uint8_t *output, size_t output_len)
{
    const struct uECC_Curve_t *secp224r1_curve = uECC_secp224r1();
    int num_words = uECC_curve_num_words(secp224r1_curve);

    uint8_t at[72];
    x963_kdf_sha256(sk, sk_len, "diversify", strlen("diversify"), at, 72);

    // I think this should be correct regardless of endianness?
    uECC_word_t one[uECC_MAX_WORDS] = {1};

    // altternative:
    // uint8_t one_raw[28] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    // uECC_vli_bytesToNative(one, one_raw, 28);

    uECC_word_t p224r1_n_minus_one[uECC_MAX_WORDS];
    uECC_vli_sub(p224r1_n_minus_one, uECC_curve_n(secp224r1_curve), one, num_words);

    uECC_word_t u_src[2 * uECC_MAX_WORDS];
    uECC_word_t v_src[2 * uECC_MAX_WORDS];
    uECC_word_t v[uECC_MAX_WORDS];
    uECC_word_t u[uECC_MAX_WORDS];

    uECC_vli_clear(u_src, 2 * uECC_MAX_WORDS);
    uECC_vli_clear(v_src, 2 * uECC_MAX_WORDS);

    uECC_vli_bytesToNative(u_src, at, 36);
    uECC_vli_bytesToNative(v_src, at + 36, 36);

    uECC_vli_mmod(u, u_src, p224r1_n_minus_one, num_words);
    uECC_vli_add(u, u, one, num_words);

    uECC_vli_mmod(v, v_src, p224r1_n_minus_one, num_words);
    uECC_vli_add(v, v, one, num_words);

    uECC_word_t orig_privkey[uECC_MAX_WORDS];
    uECC_vli_bytesToNative(orig_privkey, privkey, privkey_len);

    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_word_t derived_privkey[uECC_MAX_WORDS];
    uECC_vli_mult(product, orig_privkey, u, num_words);
    uECC_vli_add(product, product, v, num_words);
    uECC_vli_mmod(derived_privkey, product, uECC_curve_n(secp224r1_curve), num_words);

    uECC_vli_nativeToBytes(output, output_len, derived_privkey);
}

// Reimplementation of:
// https://github.com/malmeloo/FindMy.py/blob/b97b094ccae0ca0c48a3900d1320a724d988d441/findmy/accessory.py#L129-L130
void derive_skx(uint8_t *sk, size_t sk_len, uint32_t cnt)
{
    for (int i = 0; i < cnt; i++)
    {
        // note: x963_kdf_sha256 can modify value in-place if output value_len == output_len == 32!
        x963_kdf_sha256(sk, sk_len, "update", strlen("update"), sk, sk_len);
    }
}