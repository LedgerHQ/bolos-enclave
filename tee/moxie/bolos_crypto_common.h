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

/**
 * @brief Common constants and structures used by the Cryptographic API
 * @file bolos_crypto_common.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Defines common constants and structures used by BOLOS Cryptographic API
 */

#ifndef __BOLOS_CRYPTO_COMMON_H__

#define __BOLOS_CRYPTO_COMMON_H__

/* ####################################################################### */
/*                                  COMMON                                 */
/* ####################################################################### */
/*
 * Crypto mode encoding:
 * =====================
 *
 * size:
 * -----
 *  int, a least 16 bits
 *
 * encoding:
 * ---------
 *  | bit pos   |  H constant        |   meanings
 *  ---------------------------------------------------
 *  |  0        |  BLS_LAST           | last block
 *  |           |                     |
 *
 *  |  2:1      |  BLS_ENCRYPT        |
 *  |           |  BLS_DECRYPT        |
 *  |           |  BLS_SIGN           |
 *  |           |  BLS_VERIFY         |
 *
 *  |  5:3      |  BLS_PAD_NONE       |
 *  |           |  BLS_PAD_ISO9797M1  |
 *  |           |  BLS_PAD_ISO9797M2  |
 *  |           |  BLS_PAD_PKCS1_1o5  |
 *  |           |  BLS_PAD_PSS        |
 *
 *  |  7:6      |  BLS_CHAIN_ECB      |
 *  |           |  BLS_CHAIN_CBC      |
 *
 *  |  9:8      |  BLS_RND_TRNG       |
 *  |           |  BLS_RND_RFC6979    |
 *
 *  |  11:10    |  BLS_ECDH_POINT     | share full point
 *  |           |  BLS_ECDH_X         | share only x coordinate
 *  |           |  BLS_ECDH_HASHED    | return a sha256 of the x coordinate
 *
 *  |  12       |  BLS_DISCARD        | do not reinitialize context on BLS_LAST
 when supported

 *  |  14:13    |  BLS_AES_PAD_CTR    |
 *  |           |  BLS_AES_PAD_CFB    |
 *  |           |  BLS_AES_PAD_OFB    |
 *
 *  |  16:15    |  RFU                |
 */

/**
 * Bit 0
 */
#define BLS_LAST (1 << 0)

/**
 * Bit 1
 */
#define BLS_SIG_MODE (1 << 1)

/**
 * Bit 2:1
 */
#define BLS_MASK_SIGCRYPT (3 << 1)
#define BLS_ENCRYPT (2 << 1)
#define BLS_DECRYPT (0 << 1)
#define BLS_SIGN (BLS_SIG_MODE | BLS_ENCRYPT)
#define BLS_VERIFY (BLS_SIG_MODE | BLS_DECRYPT)

/**
 * Bit 5:3
 */
#define BLS_MASK_PAD (7 << 3)
#define BLS_PAD_NONE (0 << 3)
#define BLS_PAD_ISO9797M1 (1 << 3)
#define BLS_PAD_ISO9797M2 (2 << 3)
#define BLS_PAD_PKCS1_1o5 (3 << 3)
#define BLS_PAD_PSS BLS_PAD_ISO9797M1
#define BLS_PAD_PKCS5 BLS_PAD_PKCS1_1o5

/**
 * Bit 7:6
 */
#define BLS_MASK_CHAIN (3 << 6)
#define BLS_CHAIN_ECB (0 << 6)
#define BLS_CHAIN_CBC (1 << 6)

/**
 * Bit 9:8
 */
#define BLS_MASK_RND (3 << 8)
#define BLS_RND_PRNG (1 << 8)
#define BLS_RND_TRNG (2 << 8)
#define BLS_RND_RFC6979 (3 << 8)

/**
 * Bit 11:10
 */
#define BLS_MASK_ECDH (3 << 10)
#define BLS_ECDH_POINT (1 << 10)
#define BLS_ECDH_X (2 << 10)
#define BLS_ECDH_HASHED (3 << 10)

/**
 * Bit 12
 */
#define BLS_DISCARD (1 << 12)

/**
 * Bit 14:13
 */
#define BLS_MASK_AES_CHAIN (3 << 13)
#define BLS_AES_CHAIN_CTR (1 << 13)
#define BLS_AES_CHAIN_CFB (2 << 13)
#define BLS_AES_CHAIN_OFB (3 << 13)

/* ####################################################################### */
/*                                 HASH/HMAC                               */
/* ####################################################################### */

/* ======================================================================= */
/*                                   HASH                                 */
/* ======================================================================= */

enum bls_md_e {
    BLS_NONE,
    BLS_RIPEMD160,
    BLS_SHA224,
    BLS_SHA256,
    BLS_SHA384,
    BLS_SHA512,
    BLS_SHA1,
    BLS_SHA3,
    BLS_KECCAK
};
typedef enum bls_md_e bls_md_t;

#define BLS_RIPEMD160_SIZE 20
#define BLS_SHA256_SIZE 32
#define BLS_SHA512_SIZE 64

#define BLS_HASH_MAX_BLOCK_COUNT 65535

/* ####################################################################### */
/*                               CIPHER/SIGNATURE                          */
/* ####################################################################### */

/* ======================================================================= */
/*                                   DES                                   */
/* ======================================================================= */

#define BLS_DES_BLOCK_SIZE 8

/* ======================================================================= */
/*                                   AES                                   */
/* ======================================================================= */

#define BLS_AES_BLOCK_SIZE 16

/* ======================================================================= */
/*                                   RSA                                   */
/* ======================================================================= */

struct bls_rsa_crt_s {
    uint8_t WIDE *Q;
    uint32_t QSize;
    uint8_t WIDE *P;
    uint32_t PSize;
    uint8_t WIDE *DQ;
    uint32_t DQSize;
    uint8_t WIDE *DP;
    uint32_t DPSize;
    uint8_t WIDE *QInv;
    uint32_t QInvSize;
};
typedef struct bls_rsa_crt_s bls_rsa_crt_t;

struct bls_rsa_keypair_data_s {
    uint8_t *publicExponent;
    uint32_t publicExponentSize;
    uint8_t *modulus;
    uint32_t modulusSize;
    uint8_t *privateExponent;
    uint32_t privateExponentSize;
    bls_rsa_crt_t *privateCrt;
};
typedef struct bls_rsa_keypair_data_s bls_rsa_keypair_data_t;

/* ======================================================================= */
/*                                   ECDSA                                 */
/* ======================================================================= */

enum bls_curve_e {
    BLS_CURVE_NONE,
    BLS_CURVE_256K1,
    BLS_CURVE_256R1,
    BLS_CURVE_192K1,
    BLS_CURVE_192R1,
};
typedef enum bls_curve_e bls_curve_t;

/* ======================================================================= */
/*                                    CRC                                */
/* ======================================================================= */

#define BLS_CRC16_INIT 0xFFFF

#endif //__BOLOS_CRYPTO_COMMON_H__
