#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "signal.h"
#include <errno.h>
#include "bolos.h"
#include "machine.h"

#include "include/secp256k1.h"
#ifdef HAS_SCHNORR
#include "include/secp256k1_schnorr.h"
#endif
#include "include/secp256k1_ecdh.h"
#include "uECC.h"

#include "sodium/crypto_hash_sha256.h"
#include "sodium/crypto_hash_sha512.h"
#include "sodium/crypto_auth_hmacsha256.h"
#include "sodium/crypto_auth_hmacsha512.h"

#include "moxie_swi_common.h"
#include "portable_cx.h"
#include "bolos_core.h"
#include "bolos_crypto_common.h"
#include "bolos_crypto_platform_safenet.h"
#include "platform_al.h"
#include "ctaes.h"
#include "ripemd160.h"
#include "sha3.h"

#define MAX_ECFP_PUBLIC_KEYS 5
#define MAX_ECFP_PRIVATE_KEYS 5
#define MAX_RSA_KEYS 5
#define MAX_CRYPTO_SESSIONS 10
#define MAX_HASH_SESSIONS 10
#define MAX_HMAC_SESSIONS 5
#define MAX_SYMMETRIC_KEYS 10

#define MAX_RSA_LONGINT_SIZE 512
#define MAX_SYMMETRIC_KEY_SIZE 32


extern secp256k1_context *secp256k1Context;

// uECC deterministic signing

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    crypto_hash_sha256_state sha256;
} SHA256_HashContext;

void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    crypto_hash_sha256_init(&context->sha256);
}

void update_SHA256(const uECC_HashContext *base, const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    crypto_hash_sha256_update(&context->sha256, message, message_size);
}

void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    crypto_hash_sha256_final(&context->sha256, hash_result);
}

#define uECC_BYTES 32

// /uECC deterministic signing

typedef struct cryptoSession_s {
    uint8_t algorithm;
    bool available;
} cryptoSession_t;

typedef struct hashSession_t {
    union {
        crypto_hash_sha256_state sha256;
        crypto_hash_sha512_state sha512;
        RIPEMD160_CTX ripemd160;
        SHA3_CTX sha3;
    } hashAlg;
    uint8_t algorithm;
    bool available;
} hashSession_t;

typedef struct hmacSession_t {
    union {
        crypto_auth_hmacsha256_state hmacsha256;
        crypto_auth_hmacsha512_state hmacsha512;
    } hashAlg;
    uint8_t algorithm;
    bool available;
} hmacSession_t;

typedef struct symmetricKey_t {
    uint8_t keyData[MAX_SYMMETRIC_KEY_SIZE];
    uint16_t keySize;
} symmetricKey_t;

cx_ecfp_public_key_t ecfp_public_keys[MAX_ECFP_PUBLIC_KEYS];
bool ecfp_public_key_available[MAX_ECFP_PUBLIC_KEYS];
cx_ecfp_private_key_t ecfp_private_keys[MAX_ECFP_PRIVATE_KEYS];
bool ecfp_private_key_available[MAX_ECFP_PRIVATE_KEYS];
symmetricKey_t symmetricKeys[MAX_SYMMETRIC_KEYS];
bool symmetric_key_available[MAX_SYMMETRIC_KEYS];


cryptoSession_t cryptoSessions[MAX_CRYPTO_SESSIONS];
hashSession_t hashSessions[MAX_HASH_SESSIONS];
hmacSession_t hmacSessions[MAX_HMAC_SESSIONS];

const uint8_t SECP256K1_N[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                               0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                               0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

int ecdsa_der_to_sig(const uint8_t *der, uint8_t *sig) {
    int length;
    int offset = 2;
    int delta = 0;
    if (der[0] != 0x30) {
        return 0;
    }
    if (der[offset + 2] == 0) {
        length = der[offset + 1] - 1;
        offset += 3;
    } else {
        length = der[offset + 1];
        offset += 2;
    }
    if ((length < 0) || (length > uECC_BYTES)) {
        return 0;
    }
    while ((length + delta) < uECC_BYTES) {
        sig[delta++] = 0;
    }
    memmove(sig + delta, der + offset, length);

    delta = 0;
    offset += length;
    if (der[offset + 2] == 0) {
        length = der[offset + 1] - 1;
        offset += 3;
    } else {
        length = der[offset + 1];
        offset += 2;
    }
    if ((length < 0) || (length > uECC_BYTES)) {
        return 0;
    }
    while ((length + delta) < uECC_BYTES) {
        sig[uECC_BYTES + delta++] = 0;
    }
    memmove(sig + uECC_BYTES + delta, der + offset, length);

    return 1;
}

int ecdsa_sig_to_der(const uint8_t *sig, uint8_t *der) {
    int i;
    uint8_t *p = der, *len, *len1, *len2;
    *p = 0x30;
    p++; // sequence
    *p = 0x00;
    len = p;
    p++; // len(sequence)

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len1 = p;
    p++; // len(integer)

    // process R
    i = 0;
    while (sig[i] == 0 && i < 32) {
        i++;
    }                     // skip leading zeroes
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len1 = *len1 + 1;
    }
    while (i < 32) { // copy bytes to output
        *p = sig[i];
        p++;
        *len1 = *len1 + 1;
        i++;
    }

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len2 = p;
    p++; // len(integer)

    // process S
    i = 32;
    while (sig[i] == 0 && i < 64) {
        i++;
    }                     // skip leading zeroes
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len2 = *len2 + 1;
    }
    while (i < 64) { // copy bytes to output
        *p = sig[i];
        p++;
        *len2 = *len2 + 1;
        i++;
    }

    *len = *len1 + *len2 + 4;
    return *len + 2;
}

void moxie_swi_crypto_init() {
    uint32_t i;
    for (i = 0; i < MAX_ECFP_PUBLIC_KEYS; i++) {
        ecfp_public_key_available[i] = true;
    }
    for (i = 0; i < MAX_ECFP_PRIVATE_KEYS; i++) {
        ecfp_private_key_available[i] = true;
    }
    for (i = 0; i < MAX_CRYPTO_SESSIONS; i++) {
        platform_secure_memset0(&cryptoSessions[i], sizeof(cryptoSession_t));
        cryptoSessions[i].available = true;
    }
    for (i = 0; i < MAX_HASH_SESSIONS; i++) {
        hashSessions[i].available = true;
    }
    for (i = 0; i < MAX_HMAC_SESSIONS; i++) {
        hmacSessions[i].available = true;
    }
    for (i = 0; i < MAX_SYMMETRIC_KEYS; i++) {
        symmetric_key_available[i] = true;
        platform_secure_memset0(&symmetricKeys[i], sizeof(symmetricKey_t));
    }
}

void moxie_swi_crypto_cleanup() {
    uint32_t i;
    for (i = 0; i < MAX_ECFP_PUBLIC_KEYS; i++) {
        platform_secure_memset0(&ecfp_public_keys[i],
                                sizeof(cx_ecfp_public_key_t));
    }

    for (i = 0; i < MAX_ECFP_PRIVATE_KEYS; i++) {
        platform_secure_memset0(&ecfp_private_keys[i],
                                sizeof(cx_ecfp_private_key_t));
    }
    for (i = 0; i < MAX_CRYPTO_SESSIONS; i++) {
        platform_secure_memset0(&cryptoSessions[i], sizeof(cryptoSession_t));
    }
    for (i = 0; i < MAX_HASH_SESSIONS; i++) {
#ifndef SIMU
        if (hashSessions[i].hashAlg.nativeSession != NULL) {
            hashSessions[i].hashAlg.nativeSession->Free(
                hashSessions[i].hashAlg.nativeSession);
            hashSessions[i].hashAlg.nativeSession = NULL;
        }
#endif
        platform_secure_memset0(&hashSessions[i], sizeof(hashSession_t));
    }
    for (i = 0; i < MAX_HMAC_SESSIONS; i++) {
        // TODO : cleanup native
        platform_secure_memset0(&hmacSessions[i], sizeof(hmacSession_t));
    }
    for (i = 0; i < MAX_SYMMETRIC_KEYS; i++) {
        platform_secure_memset0(&symmetricKeys[i], sizeof(symmetricKey_t));
    }
}

uint8_t check_crypto_handle_allocate(bool *availableBuffer, uint32_t maxKeys,
                                     uint32_t *cryptoHandle) {
    uint32_t i;
    if (*cryptoHandle > maxKeys) {
        return 0;
    }
    if (*cryptoHandle == 0) {
        for (i = 0; i < maxKeys; i++) {
            if (availableBuffer[i]) {
                availableBuffer[i] = false;
                *cryptoHandle = i + 1;
                break;
            }
        }
    }
    return (*cryptoHandle != 0);
}

uint8_t check_crypto_handle_use(bool *availableBuffer, uint32_t maxKeys,
                                uint32_t cryptoHandle) {
    if ((cryptoHandle == 0) || (cryptoHandle > maxKeys) ||
        (availableBuffer[cryptoHandle - 1])) {
        return 0;
    }
    return 1;
}

uint8_t check_hash_handle_allocate(uint32_t *hashHandle) {
    uint32_t i;
    if (*hashHandle > MAX_HASH_SESSIONS) {
        return 0;
    }
    if (*hashHandle == 0) {
        for (i = 0; i < MAX_HASH_SESSIONS; i++) {
            if (hashSessions[i].available) {
                hashSessions[i].available = false;
                *hashHandle = i + 1;
                break;
            }
        }
    }
    return (*hashHandle != 0);
}

uint8_t check_hash_handle_use(uint32_t hashHandle) {
    if ((hashHandle == 0) || (hashHandle > MAX_HASH_SESSIONS) ||
        (hashSessions[hashHandle - 1].available)) {
        return 0;
    }
    return 1;
}

uint8_t check_hmac_handle_allocate(uint32_t *hmacHandle) {
    uint32_t i;
    if (*hmacHandle > MAX_HASH_SESSIONS) {
        return 0;
    }
    if (*hmacHandle == 0) {
        for (i = 0; i < MAX_HMAC_SESSIONS; i++) {
            if (hmacSessions[i].available) {
                hmacSessions[i].available = false;
                *hmacHandle = i + 1;
                break;
            }
        }
    }
    return (*hmacHandle != 0);
}

uint8_t check_hmac_handle_use(uint32_t hmacHandle) {
    if ((hmacHandle == 0) || (hmacHandle > MAX_HMAC_SESSIONS) ||
        (hmacSessions[hmacHandle - 1].available)) {
        return 0;
    }
    return 1;
}


/*
* bls_rng_u8
* Output:
* uint8_t
*/
void moxie_bls_rng_u8(struct machine *mach) {
    uint8_t data;
    platform_random(&data, 1);
    mach->cpu.regs[MOXIE_R0] = data;
}

/*
* bls_rng
* $r0 -- buffer uint8_t*
* $r1 -- len size_t
* Output:
* int
*/
void moxie_bls_rng(struct machine *mach) {
    uint8_t *data;
    uint32_t size = mach->cpu.regs[MOXIE_R1];
    uint32_t status = 0;
    data =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], size, true);
    if (data == NULL) {
        printf("Invalid buffer\n");
        goto end;
    }
    platform_random(data, size);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_ripemd160_init
* $r0 -- hash bls_ripemd160_t*
* Output:
* int
*/
void moxie_bls_ripemd160_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hash_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hashSessions[cryptoHandle - 1].algorithm = BLS_RIPEMD160;
    ripemd160_Init(&hashSessions[cryptoHandle - 1].hashAlg.ripemd160);
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_sha256_init
* $r0 -- hash bls_sha256_t*
* Output:
* int
*/
void moxie_bls_sha256_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hash_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hashSessions[cryptoHandle - 1].algorithm = BLS_SHA256;
    crypto_hash_sha256_init(&hashSessions[cryptoHandle - 1].hashAlg.sha256);
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_sha512_init
* $r0 -- hash bls_sha512_t*
* Output:
* int
*/
void moxie_bls_sha512_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hash_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hashSessions[cryptoHandle - 1].algorithm = BLS_SHA512;
    crypto_hash_sha512_init(&hashSessions[cryptoHandle - 1].hashAlg.sha512);
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_sha3_init
* $r0 -- hash bls_sha3_t*
* $r1 -- size int
* Output:
* int
*/
void moxie_bls_sha3_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t status = 0;
    uint32_t bits = mach->cpu.regs[MOXIE_R1];
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hash_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hashSessions[cryptoHandle - 1].algorithm = BLS_SHA3;
    switch (bits) {
    case 224:
        sha3_224_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    case 256:
        sha3_256_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    case 384:
        sha3_384_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    case 512:
        sha3_512_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    default:
        printf("Unsupported size %d\n", bits);
        hashSessions[cryptoHandle - 1].available = true;
        goto end;
    }
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_keccak_init
* $r0 -- hash bls_sha3_t*
* $r1 -- size int
* Output:
* int
*/
void moxie_bls_keccak_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t status = 0;
    uint32_t bits = mach->cpu.regs[MOXIE_R1];
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hash_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hashSessions[cryptoHandle - 1].algorithm = BLS_KECCAK;
    switch (bits) {
    case 224:
        keccak_224_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    case 256:
        keccak_256_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    case 384:
        keccak_384_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    case 512:
        keccak_512_Init(&hashSessions[cryptoHandle - 1].hashAlg.sha3);
        break;
    default:
        printf("Unsupported size %d\n", bits);
        hashSessions[cryptoHandle - 1].available = true;
        goto end;
    }
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_sha1_init
* $r0 -- hash bls_sha1_t*
* Output:
* int
*/
void moxie_bls_sha1_init(struct machine *mach) {
#ifndef SIMU
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hash_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hashSessions[cryptoHandle - 1].algorithm = BLS_SHA1;
    hashSessions[cryptoHandle - 1].algorithmNative = FMCO_IDX_SHA1;
    if (hashSessions[cryptoHandle - 1].hashAlg.nativeSession != NULL) {
        hashSessions[cryptoHandle - 1].hashAlg.nativeSession->Free(
            hashSessions[cryptoHandle - 1].hashAlg.nativeSession);
    }
    hashSessions[cryptoHandle - 1].hashAlg.nativeSession = NULL;
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
#endif
    mach->cpu.exception = SIGBUS;
}

/*
* bls_hash
* $r0 -- hash bls_hash_t*
* $r1 -- mode int
* $r2 -- in uint8_t*
* $r3 -- len size_t
* $r4 -- out uint8_t*
* Output:
* int
*/
void moxie_bls_hash(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t mode = mach->cpu.regs[MOXIE_R1];
    uint8_t *src;
    uint32_t size = mach->cpu.regs[MOXIE_R3];
    uint8_t *dest;
    uint32_t status = 0;
    uint32_t hashSize;
    uint32_t hashLen;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (!check_hash_handle_use(cryptoHandle)) {
        printf("Invalid hash handle\n");
        goto end;
    }
    switch (hashSessions[cryptoHandle - 1].algorithm) {
    case BLS_RIPEMD160:
        hashSize = 20;
        break;
    case BLS_SHA256:
        hashSize = 32;
        break;
    case BLS_SHA512:
        hashSize = 64;
        break;
    case BLS_SHA3:
    case BLS_KECCAK:
        hashSize =
            100 - (hashSessions[cryptoHandle - 1].hashAlg.sha3.block_size / 2);
        break;
    default:
        printf("Unsupported algorithm\n");
        break;
    }
    src =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2], size, false);
    if (src == NULL) {
        printf("Invalid input buffer\n");
        goto end;
    }
    dest = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4], hashSize,
                                     true);
    if (dest == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }
    if ((mode & BLS_LAST) == 0) {
        switch (hashSessions[cryptoHandle - 1].algorithm) {
        case BLS_SHA256:
            crypto_hash_sha256_update(
                &hashSessions[cryptoHandle - 1].hashAlg.sha256, src, size);
            break;
        case BLS_SHA512:
            crypto_hash_sha512_update(
                &hashSessions[cryptoHandle - 1].hashAlg.sha512, src, size);
            break;
        case BLS_RIPEMD160:
            ripemd160_Update(&hashSessions[cryptoHandle - 1].hashAlg.ripemd160,
                             src, size);
            break;
        case BLS_SHA3:
            sha3_Update(&hashSessions[cryptoHandle - 1].hashAlg.sha3, src,
                        size);
            break;
        case BLS_KECCAK:
            keccak_Update(&hashSessions[cryptoHandle - 1].hashAlg.sha3, src,
                          size);
            break;
        }
        status = 1;
    } else {
        switch (hashSessions[cryptoHandle - 1].algorithm) {
        case BLS_SHA256:
            crypto_hash_sha256_update(
                &hashSessions[cryptoHandle - 1].hashAlg.sha256, src, size);
            crypto_hash_sha256_final(
                &hashSessions[cryptoHandle - 1].hashAlg.sha256, dest);
            break;
        case BLS_SHA512:
            crypto_hash_sha512_update(
                &hashSessions[cryptoHandle - 1].hashAlg.sha512, src, size);
            crypto_hash_sha512_final(
                &hashSessions[cryptoHandle - 1].hashAlg.sha512, dest);
            break;
        case BLS_RIPEMD160:
            ripemd160_Update(&hashSessions[cryptoHandle - 1].hashAlg.ripemd160,
                             src, size);
            ripemd160_Final(&hashSessions[cryptoHandle - 1].hashAlg.ripemd160,
                            dest);
            break;
        case BLS_SHA3:
            sha3_Update(&hashSessions[cryptoHandle - 1].hashAlg.sha3, src,
                        size);
            sha3_Final(&hashSessions[cryptoHandle - 1].hashAlg.sha3, dest);
            break;
        case BLS_KECCAK:
            keccak_Update(&hashSessions[cryptoHandle - 1].hashAlg.sha3, src,
                          size);
            keccak_Final(&hashSessions[cryptoHandle - 1].hashAlg.sha3, dest);
            break;
        }
        status = hashSize;
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_hmac_ripemd160_init
* $r0 -- hmac bls_hmac_ripemd160_t*
* $r1 -- key uint8_t*
* $r2 -- key_len size_t
* Output:
* int
*/
void moxie_bls_hmac_ripemd160_init(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_hmac_sha256_init
* $r0 -- hmac bls_hmac_sha256_t*
* $r1 -- key uint8_t*
* $r2 -- key_len size_t
* Output:
* int
*/
void moxie_bls_hmac_sha256_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint8_t *key;
    uint32_t keySize = mach->cpu.regs[MOXIE_R2];
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    key = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], keySize,
                                    false);
    if (key == NULL) {
        printf("Invalid key\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hmac_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hmacSessions[cryptoHandle - 1].algorithm = BLS_SHA256;
    crypto_auth_hmacsha256_init(
        &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha256, key, keySize);
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_hmac_sha512_init
* $r0 -- hmac bls_hmac_sha512_t*
* $r1 -- key uint8_t*
* $r2 -- key_len size_t
* Output:
* int
*/
void moxie_bls_hmac_sha512_init(struct machine *mach) {
    uint32_t cryptoHandle;
    uint8_t *key;
    uint32_t keySize = mach->cpu.regs[MOXIE_R2];
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    key = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], keySize,
                                    false);
    if (key == NULL) {
        printf("Invalid key\n");
        goto end;
    }
    cryptoHandle = 0;
    if (!check_hmac_handle_allocate(&cryptoHandle)) {
        printf("Error allocating handle\n");
        goto end;
    }
    hmacSessions[cryptoHandle - 1].algorithm = BLS_SHA512;
    crypto_auth_hmacsha512_init(
        &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha512, key, keySize);
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R0], cryptoHandle);
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_hmac
* $r0 -- hmac bls_hmac_t*
* $r1 -- mode int
* $r2 -- in uint8_t*
* $r3 -- len size_t
* $r4 -- mac uint8_t*
* Output:
* int
*/
void moxie_bls_hmac(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t mode = mach->cpu.regs[MOXIE_R1];
    uint8_t *src;
    uint32_t size = mach->cpu.regs[MOXIE_R3];
    uint8_t *dest;
    uint32_t status = 0;
    uint32_t hashSize;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (!check_hmac_handle_use(cryptoHandle)) {
        printf("Invalid hmac handle\n");
        goto end;
    }
    switch (hmacSessions[cryptoHandle - 1].algorithm) {
    case BLS_SHA256:
        hashSize = 32;
        break;
    case BLS_SHA512:
        hashSize = 64;
        break;
    default:
        printf("Unsupported algorithm\n");
        break;
    }
    src =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2], size, false);
    if (src == NULL) {
        printf("Invalid input buffer\n");
        goto end;
    }
    dest = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4], hashSize,
                                     true);
    if (dest == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }

    if ((mode & BLS_LAST) == 0) {
        switch (hmacSessions[cryptoHandle - 1].algorithm) {
        case BLS_SHA256:
            crypto_auth_hmacsha256_update(
                &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha256, src, size);
            break;
        case BLS_SHA512:
            crypto_auth_hmacsha512_update(
                &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha512, src, size);
            break;
        }
        status = 1;
    } else {
        switch (hmacSessions[cryptoHandle - 1].algorithm) {
        case BLS_SHA256:
            crypto_auth_hmacsha256_update(
                &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha256, src, size);
            crypto_auth_hmacsha256_final(
                &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha256, dest);
            break;
        case BLS_SHA512:
            crypto_auth_hmacsha512_update(
                &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha512, src, size);
            crypto_auth_hmacsha512_final(
                &hmacSessions[cryptoHandle - 1].hashAlg.hmacsha512, dest);
            break;
        }
        status = hashSize;
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

void pbkdf2_sha256(uint8_t *password, uint32_t passwordSize, uint8_t *salt,
                   uint32_t saltSize, uint32_t iterations, uint8_t *buf,
                   uint32_t len) {
    crypto_auth_hmacsha256_state PShctx, hctx;
    uint32_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint32_t j;
    uint32_t k;
    uint32_t clen;

    crypto_auth_hmacsha256_init(&PShctx, password, passwordSize);
    crypto_auth_hmacsha256_update(&PShctx, salt, saltSize);

    for (i = 0; i * 32 < len; i++) {
        uint32_t counter = i + 1;
        ivec[0] = counter >> 24;
        ivec[1] = counter >> 16;
        ivec[2] = counter >> 8;
        ivec[3] = counter;
        memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha256_state));
        crypto_auth_hmacsha256_update(&hctx, ivec, 4);
        crypto_auth_hmacsha256_final(&hctx, U);

        memcpy(T, U, 32);
        /* LCOV_EXCL_START */
        for (j = 2; j <= iterations; j++) {
            crypto_auth_hmacsha256_init(&hctx, password, passwordSize);
            crypto_auth_hmacsha256_update(&hctx, U, 32);
            crypto_auth_hmacsha256_final(&hctx, U);

            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }
        /* LCOV_EXCL_STOP */

        clen = len - i * 32;
        if (clen > 32) {
            clen = 32;
        }
        memcpy(&buf[i * 32], T, clen);
    }
}

void pbkdf2_sha512(uint8_t *password, uint32_t passwordSize, uint8_t *salt,
                   uint32_t saltSize, uint32_t iterations, uint8_t *buf,
                   uint32_t len) {
    crypto_auth_hmacsha512_state PShctx, hctx;
    uint32_t i;
    uint8_t ivec[4];
    uint8_t U[64];
    uint8_t T[64];
    uint32_t j;
    uint32_t k;
    uint32_t clen;

    crypto_auth_hmacsha512_init(&PShctx, password, passwordSize);
    crypto_auth_hmacsha512_update(&PShctx, salt, saltSize);

    for (i = 0; i * 64 < len; i++) {
        uint32_t counter = i + 1;
        ivec[0] = counter >> 24;
        ivec[1] = counter >> 16;
        ivec[2] = counter >> 8;
        ivec[3] = counter;
        memcpy(&hctx, &PShctx, sizeof(crypto_auth_hmacsha512_state));
        crypto_auth_hmacsha512_update(&hctx, ivec, 4);
        crypto_auth_hmacsha512_final(&hctx, U);

        memcpy(T, U, 64);
        /* LCOV_EXCL_START */
        for (j = 2; j <= iterations; j++) {
            crypto_auth_hmacsha512_init(&hctx, password, passwordSize);
            crypto_auth_hmacsha512_update(&hctx, U, 64);
            crypto_auth_hmacsha512_final(&hctx, U);

            for (k = 0; k < 64; k++) {
                T[k] ^= U[k];
            }
        }
        /* LCOV_EXCL_STOP */

        clen = len - i * 64;
        if (clen > 64) {
            clen = 64;
        }
        memcpy(&buf[i * 64], T, clen);
    }
}

/*
* bls_pbkdf2
* $r0 -- hash bls_md_t
* $r1 -- password bls_a`rea_t*
* $r2 -- salt bls_area_t*
* $r3 -- iterations int
* $r4 -- out uint8_t*
* Output:
* int
*/
void moxie_bls_pbkdf2(struct machine *mach) {
    uint32_t hash = mach->cpu.regs[MOXIE_R0];
    bls_area_t passwordArea;
    bls_area_t saltArea;
    uint32_t iterations = mach->cpu.regs[MOXIE_R3];
    uint8_t *dest;
    uint32_t status = 0;
    if ((hash != BLS_SHA256) && (hash != BLS_SHA512)) {
        printf("Unsupported hash\n");
        goto end;
    }
    if (!moxie_var_read_bls_area(mach, mach->cpu.regs[MOXIE_R1], &passwordArea,
                                 false)) {
        printf("Invalid password\n");
        goto end;
    }
    if (!moxie_var_read_bls_area(mach, mach->cpu.regs[MOXIE_R2], &saltArea,
                                 false)) {
        printf("Invalid salt\n");
        goto end;
    }
    dest = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4], 64, true);
    if (dest == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }
    if (saltArea.length < 4) {
        printf("Invalid salt\n");
        goto end;
    }
    if (hash == BLS_SHA256) {
        pbkdf2_sha256(passwordArea.buffer, passwordArea.length, saltArea.buffer,
                      saltArea.length - 4, iterations, dest, 32);
    } else {
        pbkdf2_sha512(passwordArea.buffer, passwordArea.length, saltArea.buffer,
                      saltArea.length - 4, iterations, dest, 64);
    }
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_des_init_key
* $r0 -- rawkey uint8_t*
* $r1 -- key_len size_t
* $r2 -- key bls_des_key_t*
* Output:
* int
*/
void moxie_bls_des_init_key(struct machine *mach) {
    mach->cpu.exception = SIGBUS;

}

void moxie_bls_des_iv_mixed(struct machine *mach, bool useIV) {
    mach->cpu.exception = SIGBUS;

}

/*
* bls_des
* $r0 -- key bls_des_key_t*
* $r1 -- mode int
* $r2 -- in bls_area_t*
* $r3 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_des(struct machine *mach) {
    moxie_bls_des_iv_mixed(mach, false);
}

/*
* bls_des_iv
* $r0 -- key bls_des_key_t*
* $r1 -- mode int
* $r2 -- iv bls_area_t*
* $r3 -- in bls_area_t*
* $r4 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_des_iv(struct machine *mach) {
    moxie_bls_des_iv_mixed(mach, true);
}

/*
* bls_aes_init_key
* $r0 -- rawkey uint8_t*
* $r1 -- key_len size_t
* $r2 -- key bls_aes_key_t*
* Output:
* int
*/
void moxie_bls_aes_init_key(struct machine *mach) {
    uint8_t *key = NULL;
    uint32_t keySize = mach->cpu.regs[MOXIE_R1];
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R2],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if ((keySize != 16) && (keySize != 32)) {
        printf("Invalid key size\n");
        goto end;
    }
    key = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], keySize,
                                    false);
    if (key == NULL) {
        goto end;
    }
    if (!check_crypto_handle_allocate(symmetric_key_available,
                                      MAX_SYMMETRIC_KEYS, &cryptoHandle)) {
        printf("Invalid handle\n");
        goto end;
    }
    memmove(symmetricKeys[cryptoHandle - 1].keyData, key, keySize);
    symmetricKeys[cryptoHandle - 1].keySize = keySize;
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R2], cryptoHandle);
    status = 1;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

void moxie_bls_aes_iv_mixed(struct machine *mach, bool useIV) {
    uint32_t cryptoHandle;
    uint32_t mode = mach->cpu.regs[MOXIE_R1];
    bls_area_t src;
    bls_area_t dest;
    bool encrypt = false;
    uint32_t status = 0;
    AES128_ctx aes128_ctx;
    AES256_ctx aes256_ctx;

    if ((mode & BLS_MASK_CHAIN) != BLS_CHAIN_ECB) {
        printf("Invalid chaining\n");
        goto end;
    }

    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading private handle\n");
        goto end;
    }
    if (!check_crypto_handle_use(symmetric_key_available, MAX_SYMMETRIC_KEYS,
                                 cryptoHandle)) {
        printf("Invalid handle\n");
        goto end;
    }
    if (!moxie_var_read_bls_area(mach, mach->cpu.regs[MOXIE_R2], &src, false)) {
        printf("Invalid source\n");
        goto end;
    }
    if (!moxie_var_read_bls_area(mach, mach->cpu.regs[MOXIE_R3], &dest, true)) {
        printf("Invalid destination\n");
        goto end;
    }

    switch (mode & BLS_MASK_PAD) {
    case BLS_PAD_NONE:
        if ((src.length % 16) != 0) {
            printf("Invalid length\n");
            goto end;
        }
        break;
    default:
        printf("Invalid padding algorithm\n");
        goto end;
    }
    switch (mode & BLS_MASK_SIGCRYPT) {
    case BLS_ENCRYPT:
        encrypt = true;
        break;
    case BLS_DECRYPT:
        encrypt = false;
        break;
    default:
        printf("Invalid operation\n");
        goto end;
    }

    if ((mode & BLS_LAST) == 0) {
        printf("Update not supported\n");
        goto end;
    }

    if (symmetricKeys[cryptoHandle - 1].keySize == 16) {
        AES128_init(&aes128_ctx, symmetricKeys[cryptoHandle - 1].keyData);
    } else {
        AES256_init(&aes256_ctx, symmetricKeys[cryptoHandle - 1].keyData);
    }

    if (encrypt) {
        if (symmetricKeys[cryptoHandle - 1].keySize == 16) {
            AES128_encrypt(&aes128_ctx, src.length / 16, dest.buffer,
                           src.buffer);
        } else {
            AES256_encrypt(&aes256_ctx, src.length / 16, dest.buffer,
                           src.buffer);
        }
    } else {
        if (symmetricKeys[cryptoHandle - 1].keySize == 16) {
            AES128_decrypt(&aes128_ctx, src.length / 16, dest.buffer,
                           src.buffer);
        } else {
            AES256_decrypt(&aes256_ctx, src.length / 16, dest.buffer,
                           src.buffer);
        }
    }

    dest.length = src.length;

    moxie_var_write_bls_area_length(mach, mach->cpu.regs[MOXIE_R3],
                                    dest.length);
    status = 1;

end:
    printf("AES final status %d\n", status);
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_aes
* $r0 -- key bls_aes_key_t*
* $r1 -- mode int
* $r2 -- in bls_area_t*
* $r3 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_aes(struct machine *mach) {
    moxie_bls_aes_iv_mixed(mach, false);
}

/*
* bls_aes_iv
* $r0 -- key bls_aes_key_t*
* $r1 -- mode int
* $r2 -- iv bls_area_t*
* $r3 -- in bls_area_t*
* $r4 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_aes_iv(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_aes_iv_gcm
* $r0 -- key bls_aes_key_t*
* $r1 -- mode int
* $r2 -- in bls_area_t*
* $r3 -- iv bls_area_t*
* $r4 -- aadTag bls_area_t*
* $r5 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_aes_iv_gcm(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_rsa_init_private_key
* $r0 -- keyData bls_rsa_keypair_data_t*
* $r1 -- key bls_rsa_abstract_private_key_t*
* Output:
* int
*/
void moxie_bls_rsa_init_private_key(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_rsa_init_public_key
* $r0 -- keyData bls_rsa_keypair_data_t*
* $r1 -- key bls_rsa_abstract_public_key_t*
* Output:
* int
*/
void moxie_bls_rsa_init_public_key(struct machine *mach) {
    moxie_bls_rsa_init_private_key(mach);
}

/*
* bls_rsa_init_private_key_crt
* $r0 -- crtParameters bls_rsa_crt_t*
* $r1 -- key bls_rsa_abstract_private_key_t*
* Output:
* int
*/
void moxie_bls_rsa_init_private_key_crt(struct machine *mach) {
    // TODO : implement
    mach->cpu.exception = SIGBUS;
}

/*
* bls_rsa_generate_keypair
* $r0 -- modulus_len int
* $r1 -- privateKey bls_rsa_abstract_private_key_t*
* $r2 -- publicKey bls_rsa_abstract_public_key_t*
* $r3 -- generatedKeypairInfo bls_rsa_keypair_data_t*
* Output:
* int
*/
void moxie_bls_rsa_generate_keypair(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_rsa_get_public_key_data
* $r0 -- publicKey bls_rsa_abstract_public_key_t*
* $r1 -- keyInfo bls_rsa_keypair_data_t*
* Output:
* int
*/
void moxie_bls_rsa_get_public_key_data(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_rsa
* $r0 -- key bls_rsa_abstract_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash bls_area_t*
* $r4 -- sig bls_area_t*
* Output:
* int
*/
void moxie_bls_rsa(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_rsa_pub
* $r0 -- key bls_rsa_abstract_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- data bls_area_t*
* $r4 -- sig bls_area_t*
* Output:
* int
*/
void moxie_bls_rsa_pub(struct machine *mach) {
    moxie_bls_rsa(mach);
}

/*
* bls_rsa_priv
* $r0 -- key bls_rsa_abstract_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- data bls_area_t*
* $r4 -- sig bls_area_t*
* Output:
* int
*/
void moxie_bls_rsa_priv(struct machine *mach) {
    moxie_bls_rsa(mach);
}

/*
* bls_ecfp_get_domain
* $r0 -- curve bls_curve_t
* Output:
* bls_curve_domain_t*
*/
void moxie_bls_ecfp_get_domain(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_ecfp_is_valid_point
* $r0 -- domain bls_curve_domain_t*
* $r1 -- point uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_is_valid_point(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_ecfp_add_point
* $r0 -- domain bls_curve_domain_t*
* $r1 -- R uint8_t*
* $r2 -- P uint8_t*
* $r3 -- Q uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_add_point(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_ecdsa_init_public_key
* $r0 -- curve bls_curve_t
* $r1 -- rawkey uint8_t*
* $r2 -- key_len size_t
* $r3 -- key bls_ecfp_public_key_t*
* Output:
* int
*/
void moxie_bls_ecdsa_init_public_key(struct machine *mach) {
    uint32_t curve = mach->cpu.regs[MOXIE_R0];
    uint32_t keySize = mach->cpu.regs[MOXIE_R2];
    uint8_t *key;
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R3],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (!((keySize == 65) ||
          ((keySize == 0) && (mach->cpu.regs[MOXIE_R1] == 0)))) {
        printf("Invalid public key size\n");
        goto end;
    }
    switch (curve) {
    case BLS_CURVE_256K1:
    case BLS_CURVE_256R1:
        break;
    default:
        printf("Unsupported curve\n");
        goto end;
    }
    if (mach->cpu.regs[MOXIE_R1] != 0) {
        key = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], keySize,
                                        false);
        if (key == NULL) {
            goto end;
        }
    }
    if (!check_crypto_handle_allocate(ecfp_public_key_available,
                                      MAX_ECFP_PUBLIC_KEYS, &cryptoHandle)) {
        printf("Invalid handle\n");
        goto end;
    }

    platform_secure_memset0(&ecfp_public_keys[cryptoHandle - 1],
                            sizeof(cx_ecfp_public_key_t));
    ecfp_public_keys[cryptoHandle - 1].curve = curve;
    memmove(ecfp_public_keys[cryptoHandle - 1].W, key, keySize);
    ecfp_public_keys[cryptoHandle - 1].W_len = keySize;
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R3], cryptoHandle);
    status = 1;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_ecdsa_init_private_key
* $r0 -- curve bls_curve_t
* $r1 -- rawkey uint8_t*
* $r2 -- key_len size_t
* $r3 -- key bls_ecfp_private_key_t*
* Output:
* int
*/
void moxie_bls_ecdsa_init_private_key(struct machine *mach) {
    uint32_t curve = mach->cpu.regs[MOXIE_R0];
    uint32_t keySize = mach->cpu.regs[MOXIE_R2];
    uint8_t *key = NULL;
    uint32_t cryptoHandle;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R3],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (!((keySize == 32) ||
          ((keySize == 0) && (mach->cpu.regs[MOXIE_R1] == 0)))) {
        printf("Invalid private key size\n");
        goto end;
    }
    switch (curve) {
    case BLS_CURVE_256K1:
    case BLS_CURVE_256R1:
        break;
    default:
        printf("Unsupported curve\n");
        goto end;
    }
    if (mach->cpu.regs[MOXIE_R1] != 0) {
        key = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], keySize,
                                        false);
        if (key == NULL) {
            goto end;
        }
    }
    if (!check_crypto_handle_allocate(ecfp_private_key_available,
                                      MAX_ECFP_PRIVATE_KEYS, &cryptoHandle)) {
        printf("Invalid handle\n");
        goto end;
    }

    platform_secure_memset0(&ecfp_private_keys[cryptoHandle - 1],
                            sizeof(cx_ecfp_private_key_t));
    ecfp_private_keys[cryptoHandle - 1].curve = curve;
    memmove(ecfp_private_keys[cryptoHandle - 1].d, key, keySize);
    ecfp_private_keys[cryptoHandle - 1].d_len = keySize;
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R3], cryptoHandle);
    status = 1;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_ecfp_generate_pair
* $r0 -- curve bls_curve_t
* $r1 -- public_key bls_ecfp_public_key_t*
* $r2 -- private_key bls_ecfp_private_key_t*
* $r3 -- d uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_generate_pair(struct machine *mach) {
    uint32_t curve = mach->cpu.regs[MOXIE_R0];
    uint32_t cryptoHandle_public;
    uint32_t cryptoHandle_private;
    uint32_t status = 0;
    uint8_t *privateComponent = NULL;
    bool reuse = false;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R1],
                                      &cryptoHandle_public)) {
        printf("Error reading public handle\n");
        goto end;
    }
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R2],
                                      &cryptoHandle_private)) {
        printf("Error reading private handle\n");
        goto end;
    }
    switch (curve) {
    case BLS_CURVE_256K1:
    case BLS_CURVE_256R1:
        break;
    default:
        printf("Unsupported curve\n");
        goto end;
    }
    if (mach->cpu.regs[MOXIE_R3] != 0) {
        privateComponent =
            (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], 32, true);
        if (privateComponent == NULL) {
            goto end;
        }
    }
    if ((cryptoHandle_private != 0) &&
        (check_crypto_handle_use(ecfp_private_key_available,
                                 MAX_ECFP_PRIVATE_KEYS,
                                 cryptoHandle_private))) {
        reuse = true;
    } else {
        if (!check_crypto_handle_allocate(ecfp_private_key_available,
                                          MAX_ECFP_PRIVATE_KEYS,
                                          &cryptoHandle_private)) {
            printf("Invalid private handle\n");
            goto end;
        }
    }
    if (!check_crypto_handle_allocate(ecfp_public_key_available,
                                      MAX_ECFP_PUBLIC_KEYS,
                                      &cryptoHandle_public)) {
        printf("Invalid public handle\n");
        ecfp_private_key_available[cryptoHandle_private] = true;
        goto end;
    }
    if (curve == BLS_CURVE_256K1) {
        uint8_t tmp[32];
        secp256k1_pubkey pubkey;
        size_t length = 65;
        if (!reuse ||
            (ecfp_private_keys[cryptoHandle_private - 1].d_len == 0)) {
            for (;;) {
                platform_random(tmp, sizeof(tmp));
                if (secp256k1_ec_seckey_verify(secp256k1Context, tmp) == 1) {
                    break;
                }
            }
            memmove(ecfp_private_keys[cryptoHandle_private - 1].d, tmp, 32);
            ecfp_private_keys[cryptoHandle_private - 1].d_len = 32;
            ecfp_private_keys[cryptoHandle_private - 1].curve = curve;
        } else {
            memmove(tmp, ecfp_private_keys[cryptoHandle_private - 1].d, 32);
        }
        if (secp256k1_ec_pubkey_create(secp256k1Context, &pubkey, tmp) != 1) {
            // TODO cleanup
            printf("Error getting public key\n");
            goto end;
        }
        secp256k1_ec_pubkey_serialize(
            secp256k1Context, ecfp_public_keys[cryptoHandle_public - 1].W,
            &length, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ecfp_public_keys[cryptoHandle_public - 1].curve = curve;
        ecfp_public_keys[cryptoHandle_public - 1].W_len = length;
    } else {
        if (!reuse ||
            (ecfp_private_keys[cryptoHandle_private - 1].d_len == 0)) {
            if (!uECC_make_key(&ecfp_public_keys[cryptoHandle_public - 1].W[1],
                               ecfp_private_keys[cryptoHandle_private - 1].d,
                               uECC_secp256r1())) {
                // TODO cleanup
                printf("Error generating key\n");
                goto end;
            }
            ecfp_public_keys[cryptoHandle_public - 1].W[0] = 0x04;
            ecfp_public_keys[cryptoHandle_public - 1].curve = curve;
            ecfp_public_keys[cryptoHandle_public - 1].W_len = 65;
            ecfp_private_keys[cryptoHandle_private - 1].d_len = 32;
            ecfp_private_keys[cryptoHandle_private - 1].curve = curve;
        } else {
            if (!uECC_compute_public_key(
                    ecfp_private_keys[cryptoHandle_private - 1].d,
                    &ecfp_public_keys[cryptoHandle_public - 1].W[1],
                    uECC_secp256r1())) {
                printf("Error generating public key\n");
                goto end;
            }
            ecfp_public_keys[cryptoHandle_public - 1].W[0] = 0x04;
            ecfp_public_keys[cryptoHandle_public - 1].curve = curve;
            ecfp_public_keys[cryptoHandle_public - 1].W_len = 65;
        }
    }
    if (privateComponent != NULL) {
        memmove(privateComponent, ecfp_private_keys[cryptoHandle_private - 1].d,
                32);
    }
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R1],
                                  cryptoHandle_public);
    moxie_var_write_crypto_handle(mach, mach->cpu.regs[MOXIE_R2],
                                  cryptoHandle_private);
    status = 1;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_ecfp_get_public_component
* $r0 -- public_key bls_ecfp_public_key_t*
* $r1 -- W uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_get_public_component(struct machine *mach) {
    uint32_t cryptoHandle;
    uint8_t *publicComponent;
    uint32_t status = 0;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (!check_crypto_handle_use(ecfp_public_key_available,
                                 MAX_ECFP_PUBLIC_KEYS, cryptoHandle)) {
        printf("Invalid handle\n");
        goto end;
    }
    publicComponent =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], 65, false);
    if (publicComponent == NULL) {
        goto end;
    }
    memmove(publicComponent, ecfp_public_keys[cryptoHandle - 1].W, 65);
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_ecdsa
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_ecdsa(struct machine *mach) {
    uint32_t cryptoHandle;
    uint8_t *hash;
    uint32_t mode = mach->cpu.regs[MOXIE_R1];
    uint32_t hashId = mach->cpu.regs[MOXIE_R2];
    uint32_t hashLength = mach->cpu.regs[MOXIE_R4];
    uint32_t status = 0;
    uint8_t tmp[100];
    uint32_t signatureLength;
    uint32_t signMode = (mode & BLS_MASK_SIGCRYPT);
    uint8_t *signature;
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (signMode == BLS_SIGN) {
        if (!check_crypto_handle_use(ecfp_private_key_available,
                                     MAX_ECFP_PRIVATE_KEYS, cryptoHandle)) {
            printf("Invalid handle\n");
            goto end;
        }
    } else if (signMode == BLS_VERIFY) {
        if (!check_crypto_handle_use(ecfp_public_key_available,
                                     MAX_ECFP_PUBLIC_KEYS, cryptoHandle)) {
            printf("Invalid handle\n");
            goto end;
        }
    } else {
        goto end;
    }
    if (hashLength != 32) {
        goto end;
    }
    hash = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], hashLength,
                                     false);
    if (hash == NULL) {
        goto end;
    }
    if (signMode == BLS_VERIFY) {
        signature =
            (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R5], 2, false);
        if (signature == NULL) {
            goto end;
        }
        if (signature[0] != 0x30) {
            goto end;
        }
        signatureLength = signature[1] + 2;
        signature = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R5],
                                              signatureLength, false);
        if (signature == NULL) {
            goto end;
        }
    }

    if (signMode == BLS_SIGN) {
        if (ecfp_private_keys[cryptoHandle - 1].curve == BLS_CURVE_256K1) {
            secp256k1_ecdsa_signature sig;
            uint8_t der[100];
            size_t signatureLength = sizeof(der);
            int result = secp256k1_ecdsa_sign(
                secp256k1Context, &sig, hash,
                ecfp_private_keys[cryptoHandle - 1].d, NULL, NULL);
            if (result == 0) {
                printf("Signature failed\n");
                goto end;
            }
            if (secp256k1_ecdsa_signature_serialize_der(
                    secp256k1Context, der, &signatureLength, &sig) == 0) {
                printf("Signature serialization failed\n");
                goto end;
            }
            signature = (uint8_t *)physaddr_check(
                mach, mach->cpu.regs[MOXIE_R5], signatureLength, true);
            if (signature != NULL) {
                memmove(signature, der, signatureLength);
                status = signatureLength;
            }
        } else {
            uint8_t k[32];
            uint8_t tmp[64];
            uint8_t der[100];
            uint8_t workDeterministic[32 + 32 + 64];
            SHA256_HashContext ctx = {
                {&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
            size_t signatureLength = sizeof(der);
            if (!uECC_sign_deterministic(ecfp_private_keys[cryptoHandle - 1].d,
                                         hash, 32, &ctx.uECC, tmp,
                                         uECC_secp256r1())) {
                printf("Signature failed\n");
                goto end;
            }
            signatureLength = ecdsa_sig_to_der(tmp, der);
            signature = (uint8_t *)physaddr_check(
                mach, mach->cpu.regs[MOXIE_R5], signatureLength, true);
            if (signature != NULL) {
                memmove(signature, der, signatureLength);
                status = signatureLength;
            }
        }
    } else {
        if (ecfp_public_keys[cryptoHandle - 1].curve == BLS_CURVE_256K1) {
            secp256k1_ecdsa_signature sigInternal;
            secp256k1_pubkey pubkey;
            if (!secp256k1_ecdsa_signature_parse_der(secp256k1Context,
                                                     &sigInternal, signature,
                                                     signatureLength)) {
                printf("Unserialize DER failed\n");
                goto end;
            }
            if (secp256k1_ec_pubkey_parse(secp256k1Context, &pubkey,
                                          ecfp_public_keys[cryptoHandle - 1].W,
                                          65)) {
                int ret;
                ret = secp256k1_ecdsa_verify(secp256k1Context, &sigInternal,
                                             hash, &pubkey);
                if (ret == 1) {
                    status = 1;
                }
            }
        } else {
            uint8_t tmp[64];
            if (!ecdsa_der_to_sig(signature, tmp)) {
                printf("Unserialize DER failed\n");
                goto end;
            }
            status = uECC_verify(ecfp_public_keys[cryptoHandle - 1].W + 1, hash,
                                 32, tmp, uECC_secp256r1());
        }
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_ecdsa_sign
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_ecdsa_sign(struct machine *mach) {
    moxie_bls_ecdsa(mach);
}

/*
* bls_ecdsa_verify
* $r0 -- key bls_ecfp_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_ecdsa_verify(struct machine *mach) {
    moxie_bls_ecdsa(mach);
}

/*
* bls_schnorr
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_schnorr(struct machine *mach) {
#ifdef HAS_SCHNORR
    uint32_t cryptoHandle;
    uint8_t *hash;
    uint8_t *signature;
    uint32_t mode = mach->cpu.regs[MOXIE_R1];
    uint32_t hashId = mach->cpu.regs[MOXIE_R2];
    uint32_t hashLength = mach->cpu.regs[MOXIE_R4];
    uint32_t status = 0;
    uint32_t signMode = (mode & BLS_MASK_SIGCRYPT);
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (signMode == BLS_SIGN) {
        if (!check_crypto_handle_use(ecfp_private_key_available,
                                     MAX_ECFP_PRIVATE_KEYS, cryptoHandle)) {
            printf("Invalid handle\n");
            goto end;
        }
        if (ecfp_private_keys[cryptoHandle - 1].curve != BLS_CURVE_256K1) {
            printf("Invalid curve\n");
            goto end;
        }
    } else if (signMode == BLS_VERIFY) {
        if (!check_crypto_handle_use(ecfp_public_key_available,
                                     MAX_ECFP_PUBLIC_KEYS, cryptoHandle)) {
            printf("Invalid handle\n");
            goto end;
        }
        if (ecfp_public_keys[cryptoHandle - 1].curve != BLS_CURVE_256K1) {
            printf("Invalid curve\n");
            goto end;
        }
    } else {
        printf("Invalid mode\n");
        goto end;
    }
    if (hashLength != 32) {
        printf("Invalid hash\n");
        goto end;
    }
    hash = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], hashLength,
                                     false);
    if (hash == NULL) {
        printf("Invalid hash buffer\n");
        goto end;
    }
    signature =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R5], 64, true);
    if (signature == NULL) {
        printf("Invalid signature buffer\n");
        goto end;
    }
    if (signMode == BLS_SIGN) {
        printf("Schnorr sign\n");
        if (secp256k1_schnorr_sign(secp256k1Context, signature, hash,
                                   ecfp_private_keys[cryptoHandle - 1].d, NULL,
                                   NULL)) {
            status = 64;
        } else {
            printf("Schnorr signature failed\n");
        }
    } else if (signMode == BLS_VERIFY) {
        secp256k1_pubkey pubkey;
        printf("Schnorr verify\n");
        if (secp256k1_ec_pubkey_parse(secp256k1Context, &pubkey,
                                      ecfp_public_keys[cryptoHandle - 1].W,
                                      65)) {
            if (secp256k1_schnorr_verify(secp256k1Context, signature, hash,
                                         &pubkey)) {
                status = 1;
            } else {
                printf("Schnorr signature validation failed\n");
            }
        } else {
            printf("Invalid point\n");
        }
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
#else
    mach->cpu.regs[MOXIE_R0] = 0;
#endif
}

/*
* bls_schnorr_sign
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_schnorr_sign(struct machine *mach) {
    moxie_bls_schnorr(mach);
}

/*
* bls_schnorr_verify
* $r0 -- key bls_ecfp_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_schnorr_verify(struct machine *mach) {
    moxie_bls_schnorr(mach);
}

/*
* bls_ecdh
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- public_point uint8_t*
* $r3 -- secret uint8_t*
* Output:
* int
*/
void moxie_bls_ecdh(struct machine *mach) {
    uint32_t cryptoHandle;
    uint32_t mode = mach->cpu.regs[MOXIE_R1];
    uint8_t *publicPoint;
    uint8_t *secret;
    uint32_t status = 0;
    uint32_t secretLength = 0;
    switch (mode & BLS_MASK_ECDH) {
    case BLS_ECDH_POINT:
        secretLength = 65;
        break;
    case BLS_ECDH_X:
    case BLS_ECDH_HASHED:
        secretLength = 32;
        break;
    default:
        printf("Invalid ECDH mode\n");
        goto end;
    }
    if (!moxie_var_read_crypto_handle(mach, mach->cpu.regs[MOXIE_R0],
                                      &cryptoHandle)) {
        printf("Error reading handle\n");
        goto end;
    }
    if (!check_crypto_handle_allocate(ecfp_private_key_available,
                                      MAX_ECFP_PRIVATE_KEYS, &cryptoHandle)) {
        printf("Invalid private handle\n");
        goto end;
    }
    publicPoint =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2], 65, false);
    if (publicPoint == NULL) {
        goto end;
    }
    secret = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                       secretLength, true);
    if (secret == NULL) {
        goto end;
    }

    secp256k1_pubkey pubkey;
    if (ecfp_private_keys[cryptoHandle - 1].curve == BLS_CURVE_256K1) {
        if (!secp256k1_ec_pubkey_parse(secp256k1Context, &pubkey, publicPoint,
                                       65)) {
            printf("Invalid public point\n");
            goto end;
        }
    }
    if ((mode & BLS_MASK_ECDH) == BLS_ECDH_HASHED) {
        if (ecfp_private_keys[cryptoHandle - 1].curve != BLS_CURVE_256K1) {
            printf("Unsupported mode on this curve\n");
            goto end;
        }
        if (!secp256k1_ecdh(secp256k1Context, secret, &pubkey,
                            ecfp_private_keys[cryptoHandle - 1].d)) {
            printf("ECDH error\n");
            goto end;
        }
        status = 32;
    } else if ((mode & BLS_MASK_ECDH) == BLS_ECDH_POINT) {
        if (ecfp_private_keys[cryptoHandle - 1].curve != BLS_CURVE_256K1) {
            printf("Unsupported mode on this curve\n");
            goto end;
        } else {
#ifdef HAVE_SECP256K1_XY
            if (!secp256k1_ecdh_xy(secp256k1Context, secret, &pubkey,
                                   ecfp_private_keys[cryptoHandle - 1].d)) {
                printf("ECDH error\n");
                goto end;
            }
#else
            printf("Unsupported mode on this curve\n");
            goto end;
#endif
        }
        status = 65;
    } else if ((mode & BLS_MASK_ECDH) == BLS_ECDH_X) {
        if (ecfp_private_keys[cryptoHandle - 1].curve == BLS_CURVE_256K1) {
            printf("Unsupported mode on this curve\n");
            goto end;
        } else {
            if (!uECC_shared_secret(publicPoint + 1,
                                    ecfp_private_keys[cryptoHandle - 1].d,
                                    secret, uECC_secp256r1())) {
                printf("ECDH error\n");
                goto end;
            }
            status = 32;
        }
    } else {
        printf("Unsupported mode\n");
        goto end;
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_crc16
* $r0 -- buffer void*
* $r1 -- len size_t
* Output:
* unsigned short
*/
void moxie_bls_crc16(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_crc16_update
* $r0 -- crc unsigned short
* $r1 -- buffer void*
* $r2 -- len size_t
* Output:
* unsigned short
*/
void moxie_bls_crc16_update(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_math_addm
* $r0 -- r uint8_t*
* $r1 -- a uint8_t*
* $r2 -- b uint8_t*
* $r3 -- m uint8_t*
* $r4 -- len size_t
* Output:
* void
*/
void moxie_bls_math_addm(struct machine *mach) {
    uint8_t *r;
    uint8_t *a;
    uint8_t *b;
    uint8_t *m;
    uint32_t len = mach->cpu.regs[MOXIE_R4];
    uint32_t status = 0;
    if (len != 32) {
        printf("Unsupported length\n");
        goto end;
    }
    r = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], len, false);
    if (r == NULL) {
        goto end;
    }
    a = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], len, false);
    if (a == NULL) {
        goto end;
    }
    b = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2], len, false);
    if (r == NULL) {
        goto end;
    }
    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], len, false);
    if (m == NULL) {
        goto end;
    }
    if (memcmp(m, SECP256K1_N, 32) != 0) {
        printf("Unsupported domain\n");
        goto end;
    }
    if (!secp256k1_ec_privkey_tweak_add(secp256k1Context, a, b)) {
        printf("Error secp256k1_ec_privkey_tweak_add\n");
        goto end;
    }
    memmove(r, a, len);
    status = len;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_math_cmp
* $r0 -- a uint8_t*
* $r1 -- b uint8_t*
* $r2 -- len size_t
* Output:
* int
*/
void moxie_bls_math_cmp(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_math_is_zero
* $r0 -- a uint8_t*
* $r1 -- len size_t
* Output:
* int
*/
void moxie_bls_math_is_zero(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_math_modm
* $r0 -- v uint8_t*
* $r1 -- len_v size_t
* $r2 -- m uint8_t*
* $r3 -- len_m size_t
* Output:
* void
*/
void moxie_bls_math_modm(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_wallet_derive
* $r0 -- details uint8_t
* $r1 -- path uint32_t*
* $r2 -- pathLength size_t
* $r3 -- chainCode uint8_t*
* $r4 -- privateKey bls_ecfp_private_key_t*
* $r5 -- publicKey bls_ecfp_public_key_t*
* Output:
* int
*/
void moxie_bls_wallet_derive(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_wallet_get_address
* $r0 -- publicKey bls_ecfp_public_key_t*
* $r1 -- address char*
* $r2 -- addressLength size_t
* $r3 -- compressed uint8_t
* Output:
* int
*/
void moxie_bls_wallet_get_address(struct machine *mach) {
    mach->cpu.exception = SIGBUS;
}

/*
* bls_bip32_derive_secp256k1_private
* $r0 -- privateKey uint8_t*
* $r1 -- chainCode uint8_t*
* $r2 -- index uint32_t
* Output:
* int
*/
void moxie_bls_bip32_derive_secp256k1_private(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *privateKey;
    uint8_t *chainCode;
    uint32_t index = mach->cpu.regs[MOXIE_R2];
    uint8_t tmp[64];
    crypto_auth_hmacsha512_state hmac;
    privateKey =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], 32, true);
    if ((privateKey == NULL) ||
        (secp256k1_ec_seckey_verify(secp256k1Context, privateKey) != 1)) {
        goto end;
    }
    chainCode =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], 32, true);
    if (chainCode == NULL) {
        goto end;
    }
    if ((index & 0x80000000) != 0) {
        tmp[0] = 0;
        memmove(tmp + 1, privateKey, 32);
    } else {
        secp256k1_pubkey pubkey;
        size_t length = 33;
        if ((secp256k1_ec_pubkey_create(secp256k1Context, &pubkey,
                                        privateKey) != 1) ||
            (secp256k1_ec_pubkey_serialize(secp256k1Context, tmp, &length,
                                           &pubkey,
                                           SECP256K1_EC_COMPRESSED) != 1)) {
            goto end;
        }
    }
    tmp[33] = ((index >> 24) & 0xff);
    tmp[34] = ((index >> 16) & 0xff);
    tmp[35] = ((index >> 8) & 0xff);
    tmp[36] = (index & 0xff);
    crypto_auth_hmacsha512_init(&hmac, chainCode, 32);
    crypto_auth_hmacsha512_update(&hmac, tmp, 37);
    crypto_auth_hmacsha512_final(&hmac, tmp);
    if (secp256k1_ec_privkey_tweak_add(secp256k1Context, privateKey, tmp) !=
        1) {
        goto end;
    }
    memmove(chainCode, tmp + 32, 32);
    status = 1;

end:
    platform_secure_memset0(tmp, sizeof(tmp));
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_bip32_derive_secp256k1_public
* $r0 -- publicKey uint8_t*
* $r1 -- chainCode uint8_t*
* $r2 -- index uint32_t
* Output:
* int
*/
void moxie_bls_bip32_derive_secp256k1_public(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *publicKey;
    uint8_t *chainCode;
    uint32_t index = mach->cpu.regs[MOXIE_R2];
    uint8_t tmp[64];
    crypto_auth_hmacsha512_state hmac;
    secp256k1_pubkey pubkey;
    size_t length = 33;
    publicKey =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], 33, true);
    if ((publicKey == NULL) ||
        (secp256k1_ec_pubkey_parse(secp256k1Context, &pubkey, publicKey, 33) !=
         1)) {
        goto end;
    }
    chainCode =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], 32, true);
    if (chainCode == NULL) {
        goto end;
    }
    if ((index & 0x80000000) != 0) {
        goto end;
    } else {
        memmove(tmp, publicKey, 33);
    }
    tmp[33] = ((index >> 24) & 0xff);
    tmp[34] = ((index >> 16) & 0xff);
    tmp[35] = ((index >> 8) & 0xff);
    tmp[36] = (index & 0xff);
    crypto_auth_hmacsha512_init(&hmac, chainCode, 32);
    crypto_auth_hmacsha512_update(&hmac, tmp, 37);
    crypto_auth_hmacsha512_final(&hmac, tmp);
    if ((secp256k1_ec_pubkey_tweak_add(secp256k1Context, &pubkey, tmp) != 1) ||
        (secp256k1_ec_pubkey_serialize(secp256k1Context, publicKey, &length,
                                       &pubkey,
                                       SECP256K1_EC_COMPRESSED) != 1)) {
        goto end;
    }
    memmove(chainCode, tmp + 32, 32);
    status = 1;

end:
    platform_secure_memset0(tmp, sizeof(tmp));
    mach->cpu.regs[MOXIE_R0] = status;
}
