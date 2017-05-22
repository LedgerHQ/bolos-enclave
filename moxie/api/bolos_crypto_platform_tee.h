/*
*******************************************************************************
*   BOLOS TEE
*   (c) 2016, 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

/**
 * @brief TEE HAL of the Cryptographic API
 * @file bolos_crypto_platform_tee.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Defines specific constants and structures used by BOLOS TEE Cryptographic API
 * implementation
 */

#ifndef __BOLOS_CRYPTO_PLATFORM_TEE_H__

#define __BOLOS_CRYPTO_PLATFORM_TEE_H__

typedef uint32_t bls_crypto_handle_t;

struct bls_ripemd160_s {
    bls_crypto_handle_t header;
};
typedef struct bls_ripemd160_s bls_ripemd160_t;

struct bls_sha256_s {
    bls_crypto_handle_t header;
};
typedef struct bls_sha256_s bls_sha256_t;

struct bls_sha512_s {
    bls_crypto_handle_t header;
};
typedef struct bls_sha512_s bls_sha512_t;

struct bls_sha3_s {
    bls_crypto_handle_t header;
};
typedef struct bls_sha3_s bls_sha3_t;

struct bls_sha1_s {
    bls_crypto_handle_t header;
};
typedef struct bls_sha1_s bls_sha1_t;

// typedef struct bls_crypto_handle_t     bls_hash_t;
typedef bls_crypto_handle_t bls_hash_t;

/* ======================================================================= */
/*                                 HASH MAC                                */
/* ======================================================================= */

struct bls_hmac_ripemd160_s {
    bls_crypto_handle_t handle;
};
typedef struct bls_hmac_ripemd160_s bls_hmac_ripemd160_t;

struct bls_hmac_sha256_s {
    bls_crypto_handle_t handle;
};
typedef struct bls_hmac_sha256_s bls_hmac_sha256_t;

struct bls_hmac_sha512_s {
    bls_crypto_handle_t handle;
};
typedef struct bls_hmac_sha512_s bls_hmac_sha512_t;

struct bls_hmac_s {
    bls_crypto_handle_t handle;
};
typedef struct bls_hmac_s bls_hmac_t;

/* ####################################################################### */
/*                               CIPHER/SIGNATURE                          */
/* ####################################################################### */
/* - DES
 * - ECDSA
 * - ECDH
 * - RSA
 */

/* ======================================================================= */
/*                                   DES                                   */
/* ======================================================================= */

#define CX_DES_BLOCK_SIZE 8

struct bls_des_key_s {
    bls_crypto_handle_t handle;
};

typedef struct bls_des_key_s bls_des_key_t;

/* ======================================================================= */
/*                                   AES                                   */
/* ======================================================================= */

struct bls_aes_key_s {
    bls_crypto_handle_t handle;
};

typedef struct bls_aes_key_s bls_aes_key_t;

/* ======================================================================= */
/*                                   RSA                                   */
/* ======================================================================= */

struct bls_rsa_abstract_public_key_s {
    bls_crypto_handle_t handle;
};
typedef struct bls_rsa_abstract_public_key_s bls_rsa_abstract_public_key_t;

struct bls_rsa_abstract_private_key_s {
    bls_crypto_handle_t handle;
};
typedef struct bls_rsa_abstract_private_key_s bls_rsa_abstract_private_key_t;

/* ======================================================================= */
/*                                   ECDSA                                 */
/* ======================================================================= */

typedef struct bls_curve_domain_s { bls_curve_t curve; } bls_curve_domain_t;

struct bls_ecfp_public_key_s {
    bls_crypto_handle_t handle;
};

struct bls_ecfp_private_key_s {
    bls_crypto_handle_t handle;
};

typedef struct bls_ecfp_public_key_s bls_ecfp_public_key_t;
typedef struct bls_ecfp_private_key_s bls_ecfp_private_key_t;

#endif //__BOLOS_CRYPTO_PLATFORM_TEE_H__
