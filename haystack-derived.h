#include <stdint.h>
#include <uECC_vli.h>

// This is correct for secp224r1, it's fine...
#define uECC_MAX_WORDS 7

// Quick and dirty X9.63-SHA256-KDF. Only supports output_len <8K.
void x963_kdf_sha256(
    uint8_t *value, size_t value_len,
    uint8_t *sn, size_t sn_len,
    uint8_t *output, size_t output_len);

// Perform SKx rotation. Modifies sk buffer in-place.
void derive_skx(uint8_t *sk, size_t sk_len, uint32_t cnt);

// Derive final keypair from master key and SKx.
void derive_ps_key(uint8_t *privkey, size_t privkey_len, uint8_t *sk, size_t sk_len, uint8_t *output, size_t output_len);