/*******************************************************************************
*   BOLOS Enclave
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bolos.h"
#include "machine.h"

#include "include/secp256k1.h"
#include "sodium.h"

#include "machine.h"
#include "portable_msg.h"
#include "portable_persistent_context.h"
#include "portable_transient_context.h"
#include "signal.h"

#include "sodium/crypto_hash_sha256.h"
#include "sodium/crypto_hash_sha512.h"
#include "sodium/crypto_auth_hmacsha256.h"
#include "sodium/crypto_auth_hmacsha512.h"

#include "moxie_swi_common.h"
#include "bolos_core.h"
#include "bolos_crypto_common.h"
#include "bolos_wrapping.h"
#include "bolos_endorsement.h"
#include "platform_al.h"
#include "platform_persistent_context.h"

extern secp256k1_context *secp256k1Context;
extern bolos_transient_context_t bolosTransientContext;

bool endorsement1_available() {
    bool supported = false;
    bolos_persistent_context_t bolosPersistentContext;
    if (platform_read_persistent_context(&bolosPersistentContext)) {
        supported =
            ((bolosPersistentContext.endorsement_private_key1.d_len == 32) &&
             (bolosPersistentContext.endorsement_key1_certificate_length != 0));
    }
    return supported;
}

bool endorsement2_available() {
    bool supported = false;
    bolos_persistent_context_t bolosPersistentContext;
    if (platform_read_persistent_context(&bolosPersistentContext)) {
        supported =
            ((bolosPersistentContext.endorsement_private_key2.d_len == 32) &&
             (bolosPersistentContext.endorsement_key2_certificate_length != 0));
    }
    return supported;
}

/*
* bls_endorsement_supported
* * $r0 -- key bls_endorsement_key_e
* Output:
* int
*/
void moxie_bls_endorsement_supported(struct machine *mach) {
    uint32_t keyReference = mach->cpu.regs[MOXIE_R0];
    uint32_t status = 0;
    if ((keyReference != BLS_ENDORSEMENT_KEY1) &&
        (keyReference != BLS_ENDORSEMENT_KEY2)) {
        printf("Unsupported key reference\n");
        goto end;
    }
    if (keyReference == BLS_ENDORSEMENT_KEY1) {
        status = (endorsement1_available() ? 1 : 0);
    } else {
        status = (endorsement2_available() ? 1 : 0);
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_get_authentication_public_key
* $r0 -- out uint8_t*
* $r1 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_authentication_public_key(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = 0;
}

/*
* bls_endorsement_init
* $r0 -- key bls_endorsement_key_e
* $r1 -- out uint8_t*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_init(struct machine *mach) {
    uint32_t keyReference = mach->cpu.regs[MOXIE_R0];
    uint8_t *out;
    uint32_t outLength = mach->cpu.regs[MOXIE_R2];
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;
    unsigned short certificateLength = 0;
    uint32_t status = 0;
    secp256k1_pubkey pubkey;
    size_t length = 65;
    bolos_persistent_context_t bolosPersistentContext;

    if ((keyReference != BLS_ENDORSEMENT_KEY1) &&
        (keyReference != BLS_ENDORSEMENT_KEY2)) {
        printf("Unsupported key reference\n");
        goto end;
    }

    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], 65, true);
    if (out == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }

    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }

    // Initialize a keypair
    for (;;) {
        platform_random(privateKey.d, sizeof(privateKey.d));
        if (secp256k1_ec_seckey_verify(secp256k1Context, privateKey.d) == 1) {
            break;
        }
    }
    if (secp256k1_ec_pubkey_create(secp256k1Context, &pubkey, privateKey.d) !=
        1) {
        platform_secure_memset0(&privateKey, sizeof(cx_ecfp_private_key_t));
        printf("Error getting public key\n");
        goto end;
    }
    secp256k1_ec_pubkey_serialize(secp256k1Context, publicKey.W, &length,
                                  &pubkey, SECP256K1_EC_UNCOMPRESSED);
    privateKey.d_len = 32;
    publicKey.W_len = 65;
    publicKey.curve = CX_CURVE_256K1;

    if (keyReference == BLS_ENDORSEMENT_KEY1) {
        memmove(&bolosPersistentContext.endorsement_private_key1, &privateKey,
                sizeof(cx_ecfp_private_key_t));
        if (!platform_sha256_init() ||
            !platform_sha256_update(privateKey.d, 32) ||
            !platform_sha256_final(
                bolosPersistentContext.endorsement_private_key1_hash)) {
            platform_secure_memset0(&privateKey, sizeof(cx_ecfp_private_key_t));
            printf("Error diversifying key\n");
            goto end;
        }
    } else {
        memmove(&bolosPersistentContext.endorsement_private_key2, &privateKey,
                sizeof(cx_ecfp_private_key_t));
    }

    platform_secure_memset0(&privateKey, sizeof(cx_ecfp_private_key_t));

    memmove(out, publicKey.W, 65);

    platform_write_persistent_context(&bolosPersistentContext);

    status = 65;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_commit
* $r0 -- key bls_endorsement_key_e
* $r1 -- response uint8_t*
* $r2 -- responseLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_commit(struct machine *mach) {
    uint32_t keyReference = mach->cpu.regs[MOXIE_R0];
    uint8_t *in;
    uint16_t inLength = mach->cpu.regs[MOXIE_R2];
    uint32_t status = 0;
    bolos_persistent_context_t bolosPersistentContext;
    if ((keyReference != BLS_ENDORSEMENT_KEY1) &&
        (keyReference != BLS_ENDORSEMENT_KEY2)) {
        printf("Unsupported key reference\n");
        goto end;
    }
    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }
    in = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], inLength,
                                   false);
    if (in == NULL) {
        printf("Invalid parameter\n");
        goto end;
    }
    if (keyReference == BLS_ENDORSEMENT_KEY1) {
        memmove(bolosPersistentContext.endorsement_key1_certificate, in,
                inLength);
        memmove(&bolosPersistentContext.endorsement_key1_certificate_length,
                &inLength, sizeof(uint16_t));
    } else {
        memmove(bolosPersistentContext.endorsement_key2_certificate, in,
                inLength);
        memmove(&bolosPersistentContext.endorsement_key2_certificate_length,
                &inLength, sizeof(uint16_t));
    }

    platform_write_persistent_context(&bolosPersistentContext);

    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_get_code_hash
* $r0 -- out uint8_t*
* $r1 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_code_hash(struct machine *mach) {
    uint8_t *out;
    uint32_t outLength = mach->cpu.regs[MOXIE_R1];
    uint32_t status = 0;
    out = (uint8_t *)physaddr_check(
        mach, mach->cpu.regs[MOXIE_R0],
        sizeof(bolosTransientContext.runningExecCodeHash), true);
    if (out == NULL) {
        printf("Invalid parameter\n");
        goto end;
    }
    memmove(out, bolosTransientContext.runningExecCodeHash,
            sizeof(bolosTransientContext.runningExecCodeHash));
    status = sizeof(bolosTransientContext.runningExecCodeHash);
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_key1_get_app_secret
* $r0 -- out uint8_t*
* $r1 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_key1_get_app_secret(struct machine *mach) {
    uint8_t *out;
    uint8_t out2[64];
    uint32_t outLength = mach->cpu.regs[MOXIE_R1];
    uint32_t status = 0;
    bolos_persistent_context_t bolosPersistentContext;
    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }
    if (!endorsement1_available()) {
        printf("Endorsement not available\n");
        goto end;
    }
    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], 64, true);
    if (out == NULL) {
        printf("Invalid parameter\n");
        goto end;
    }

    crypto_auth_hmacsha512(
        out2, bolosTransientContext.runningExecCodeHash,
        sizeof(bolosTransientContext.runningExecCodeHash),
        bolosPersistentContext.endorsement_private_key1_hash);
    memmove(out, out2, 64);
    status = 64;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_key1_sign_data
* $r0 -- in uint8_t*
* $r1 -- length size_t
* $r2 -- out uint8_t*
* $r3 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_key1_sign_data(struct machine *mach) {
    uint8_t *in;
    uint32_t inLength = mach->cpu.regs[MOXIE_R1];
    uint8_t *out;
    uint32_t outLength = mach->cpu.regs[MOXIE_R3];
    uint32_t status = 0;
    bolos_persistent_context_t bolosPersistentContext;
    unsigned char tmp[32];
    secp256k1_ecdsa_signature sig;
    uint8_t der[100];
    size_t signatureLength = sizeof(der);

    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }
    if (!endorsement1_available()) {
        printf("Endorsement not available\n");
        goto end;
    }
    in = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], inLength,
                                   false);
    if (in == NULL) {
        printf("Invalid input parameter\n");
        goto end;
    }

    if (!platform_sha256_init() || !platform_sha256_update(in, inLength) ||
        !platform_sha256_update(
            bolosTransientContext.runningExecCodeHash,
            sizeof(bolosTransientContext.runningExecCodeHash)) ||
        !platform_sha256_final(tmp)) {
        printf("Error computing hash\n");
        goto end;
    }

    int result = secp256k1_ecdsa_sign(
        secp256k1Context, &sig, tmp,
        bolosPersistentContext.endorsement_private_key1.d, NULL, NULL);
    if (result == 0) {
        printf("Signature failed\n");
        goto end;
    }
    if (secp256k1_ecdsa_signature_serialize_der(secp256k1Context, der,
                                                &signatureLength, &sig) == 0) {
        printf("Signature serialization failed\n");
        goto end;
    }
    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2],
                                    signatureLength, true);
    if (out != NULL) {
        memmove(out, der, signatureLength);
        status = signatureLength;
    } else {
        printf("Invalid output buffer\n");
    }

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_key2_derive_sign_data
* $r0 -- in uint8_t*
* $r1 -- length size_t
* $r2 -- out uint8_t*
* $r3 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_key2_derive_sign_data(struct machine *mach) {
    uint8_t *in;
    uint32_t inLength = mach->cpu.regs[MOXIE_R1];
    uint8_t *out;
    uint32_t outLength = mach->cpu.regs[MOXIE_R3];
    uint32_t status = 0;
    bolos_persistent_context_t bolosPersistentContext;
    uint8_t privateKey[32];
    secp256k1_pubkey pubkey;
    uint8_t pubkeyComponent[65];
    size_t pubkeyLength = 65;
    uint8_t tmp[32];
    uint8_t hash[32];
    secp256k1_ecdsa_signature sig;
    uint8_t der[100];
    size_t signatureLength = sizeof(der);

    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }
    if (!endorsement2_available()) {
        printf("Endorsement not available\n");
        goto end;
    }
    in = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], inLength,
                                   false);
    if (in == NULL) {
        printf("Invalid input parameter\n");
        goto end;
    }

    if (secp256k1_ec_pubkey_create(
            secp256k1Context, &pubkey,
            bolosPersistentContext.endorsement_private_key2.d) != 1) {
        printf("Error recovering public key\n");
        goto end;
    }
    secp256k1_ec_pubkey_serialize(secp256k1Context, pubkeyComponent,
                                  &pubkeyLength, &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);

    crypto_auth_hmacsha256(tmp, pubkeyComponent, sizeof(pubkeyComponent),
                           bolosTransientContext.runningExecCodeHash);
    if (!secp256k1_ec_privkey_tweak_add(
            secp256k1Context, tmp,
            bolosPersistentContext.endorsement_private_key2.d)) {
        printf("Error secp256k1_ec_privkey_tweak_add\n");
        goto end;
    }

    if (!platform_sha256_init() || !platform_sha256_update(in, inLength) ||
        !platform_sha256_final(hash)) {
        printf("Error computing hash\n");
        goto end;
    }

    int result =
        secp256k1_ecdsa_sign(secp256k1Context, &sig, hash, tmp, NULL, NULL);
    if (result == 0) {
        printf("Signature failed\n");
        goto end;
    }
    if (secp256k1_ecdsa_signature_serialize_der(secp256k1Context, der,
                                                &signatureLength, &sig) == 0) {
        printf("Signature serialization failed\n");
        goto end;
    }

    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2],
                                    signatureLength, true);
    if (out != NULL) {
        memmove(out, der, signatureLength);
        status = signatureLength;
    } else {
        printf("Invalid output buffer\n");
    }

end:
    platform_secure_memset0(privateKey, sizeof(privateKey));
    platform_secure_memset0(tmp, sizeof(tmp));
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_get_public_key
* $r0 -- endorsementKey bls_endorsement_key_t
* $r1 -- out uint8_t*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_public_key(struct machine *mach) {
    uint32_t keyReference = mach->cpu.regs[MOXIE_R0];
    uint8_t *out;
    uint16_t outLength = mach->cpu.regs[MOXIE_R2];
    uint32_t status = 0;
    bolos_persistent_context_t bolosPersistentContext;
    secp256k1_pubkey pubkey;
    uint8_t pubkeyComponent[65];
    size_t pubkeyLength = 65;

    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }

    if (keyReference == BLS_ENDORSEMENT_KEY1) {
        if (!endorsement1_available()) {
            printf("Endorsement not available\n");
            goto end;
        }
    } else if (keyReference == BLS_ENDORSEMENT_KEY2) {
        if (!endorsement2_available()) {
            printf("Endorsement not available\n");
            goto end;
        }
    } else {
        printf("Unsupported key reference\n");
        goto end;
    }
    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], 65, true);
    if (out == NULL) {
        printf("Invalid parameter\n");
        goto end;
    }

    if (secp256k1_ec_pubkey_create(
            secp256k1Context, &pubkey,
            (keyReference == BLS_ENDORSEMENT_KEY1
                 ? bolosPersistentContext.endorsement_private_key1.d
                 : bolosPersistentContext.endorsement_private_key2.d)) != 1) {
        printf("Error recovering public key\n");
        goto end;
    }
    secp256k1_ec_pubkey_serialize(secp256k1Context, pubkeyComponent,
                                  &pubkeyLength, &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);
    memmove(out, pubkeyComponent, 65);
    status = 65;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_endorsement_get_certificate
* $r0 -- endorsementKey bls_endorsement_key_t
* $r1 -- out uint8_t*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_certificate(struct machine *mach) {
    uint32_t keyReference = mach->cpu.regs[MOXIE_R0];
    uint8_t *out;
    uint16_t outLength = mach->cpu.regs[MOXIE_R2];
    uint32_t status = 0;
    uint8_t *certificate;
    uint32_t certificateLength;
    bolos_persistent_context_t bolosPersistentContext;

    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        printf("Cannot read persistent context\n");
        goto end;
    }
    if (keyReference == BLS_ENDORSEMENT_KEY1) {
        if (!endorsement1_available()) {
            printf("Endorsement not available\n");
            goto end;
        }
        certificate = bolosPersistentContext.endorsement_key1_certificate;
        certificateLength =
            bolosPersistentContext.endorsement_key1_certificate_length;
    } else if (keyReference == BLS_ENDORSEMENT_KEY2) {
        if (!endorsement2_available()) {
            printf("Endorsement not available\n");
            goto end;
        }
        certificate = bolosPersistentContext.endorsement_key2_certificate;
        certificateLength =
            bolosPersistentContext.endorsement_key2_certificate_length;
    } else {
        printf("Unsupported key reference\n");
        goto end;
    }
    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1],
                                    certificateLength, true);
    if (out == NULL) {
        printf("Invalid parameter\n");
        goto end;
    }
    memmove(out, certificate, certificateLength);
    status = certificateLength;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}
