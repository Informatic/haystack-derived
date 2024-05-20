#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <uECC.h>
#include <b64.h>

#include "haystack-derived.h"

#define PRIVKEY_LEN 28l
#define SK_LEN 32l

void hexdump(uint8_t *buffer, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
    {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s base64-privkey base64-sk [index]\n", argv[0]);
        return 1;
    }

    size_t privkey_len = 0;
    uint8_t *privkey = b64_decode_ex(argv[1], strlen(argv[1]), &privkey_len);

    if (privkey_len != PRIVKEY_LEN)
    {
        fprintf(stderr, "Invalid private key length, got %ld expected %ld\n", privkey_len, PRIVKEY_LEN);
        return 1;
    }

    size_t sk_len = 0;
    uint8_t *sk = b64_decode_ex(argv[2], strlen(argv[2]), &sk_len);

    if (sk_len != SK_LEN)
    {
        fprintf(stderr, "Invalid SKx length, got %ld expected %ld\n", sk_len, SK_LEN);
        return 1;
    }

    printf("Privkey length: %ld; SKx length: %ld\n", privkey_len, sk_len);

    const struct uECC_Curve_t *secp224r1_curve = uECC_secp224r1();
    uint8_t pubkey[28 * 2];
    int res = uECC_compute_public_key(privkey, pubkey, secp224r1_curve);
    if (res != 1)
    {
        fprintf(stderr, "Pubkey compute failed\n");
        return res;
    }

    char *pubkey_x_b64 = b64_encode(pubkey, 28);
    char *pubkey_y_b64 = b64_encode(pubkey + 28, 28);
    printf("Pubkey X: %s / ", pubkey_x_b64);
    hexdump(pubkey, 28);
    printf("Pubkey Y: %s / ", pubkey_y_b64);
    hexdump(pubkey + 28, 28);

    int index = 1;
    if (argc >= 4)
    {
        index = atoi(argv[3]);
    }

    printf("Deriving SKx with index %d...\n", index);
    derive_skx(sk, sk_len, index);

    uint8_t derived_key[28];
    derive_ps_key(privkey, privkey_len, sk, sk_len, derived_key, 28);

    printf("Derived privkey: ");
    hexdump(derived_key, 28);

    res = uECC_compute_public_key(derived_key, pubkey, secp224r1_curve);
    if (res != 1)
    {
        fprintf(stderr, "Derived pubkey compute failed\n");
        return 1;
    }

    printf("Derived pubkeyX: ");
    hexdump(pubkey, 28);
}
