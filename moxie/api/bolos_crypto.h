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
 * @brief Generic Cryptographic API
 * @file bolos_crypto.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Perform general purpose cryptographic operations
 *
 * In this release, the API doesn't implement exceptions
 */

#ifndef __BOLOS_CRYPTO_H__

#define __BOLOS_CRYPTO_H__

/* ####################################################################### */
/*                                   RAND                                  */
/* ####################################################################### */

/**
 * @brief generate a random byte
 *
 * @return random byte
 */
uint8_t bls_rng_u8(void);

/**
 * @brief generate a random buffer
 *
 * @param [out] buffer the buffer containing the random data
 * @param [in] len length of the random buffer to generate
 * @return 1 if success, 0 if error
 */
int bls_rng(uint8_t *buffer, size_t len);

/* ####################################################################### */
/*                                 HASH/HMAC                               */
/* ####################################################################### */

/* ======================================================================= */
/*                                   HASH                                 */
/* ======================================================================= */

/**
 * @brief Initialize a ripmd160 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return 1 if success, 0 if error
 */
int bls_ripemd160_init(bls_ripemd160_t *hash);

/**
 * @brief Initialize a sha1 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return 1 if success, 0 if error
 */
int bls_sha1_init(bls_sha1_t *hash);

/**
 * @brief Initialize a sha256 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return 1 if success, 0 if error
 */
int bls_sha256_init(bls_sha256_t *hash);

/**
 * @brief Initialize a sha512 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return 1 if success, 0 if error
 */
int bls_sha512_init(bls_sha512_t *hash);

/**
 * @brief Initialize a sha3 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @param [in] size output size, in bits
 * (valid 224, 256, 384, 512)
 *
 * @return 1 if success, 0 if error
 */
int bls_sha3_init(bls_sha3_t *hash, int size);

/**
 * @brief Initialize a Keccak (pre-release sha3) context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @param [in] size output size, in bits
 * (valid 224, 256, 384, 512)
 *
 * @return 1 if success, 0 if error
 */
int bls_keccak_init(bls_sha3_t *hash, int size);

/**
 * @brief Add more data to hash.
 *
 * @param  [in,out] hash
 *   Hash context
 *   The hash context pointer shall point to  either a bls_ripemd160_t, either a
 * bls_sha256_t  or bls_sha512_t .
 *   The hash context shall be inited with 'bls_xxx_init'
 *   The hash context shall be in RAM
 *   The function should be called with a nice cast.
 *
 * @param  [in] mode
 *   16bits flags. See Above
 *   If BLS_LAST is set, context is automatically re-inited.
 *   Supported flags:
 *     - BLS_LAST
 *
 * @param  [in] in
 *   Input data to add to current hash
 *
 * @param  [in] len
 *   Length of input to data.
 *
 * @param [out] out
 *   Either:
 *     - NULL (ignored) if BLS_LAST is NOT set
 *     - produced hash  if BLS_LAST is set
 *   'out' length is implicit, no check is done
 *
 * @return 1 if success, not finished. Hash size if success, finished. 0 if
 * error
 */
int bls_hash(bls_hash_t *hash, int mode, const uint8_t WIDE *in, size_t len,
             uint8_t *out);

/* ======================================================================= */
/*                                 HASH MAC                                */
/* ======================================================================= */

/**
 * @brief Initialize a HMAC sha512 context.
 *
 * @param  [out] hmac        the context to init.
 *    The context shall be in RAM
 *
 * @param  [in] key         hmac key value
 *    Passing a NULL pointeur, will reinit the context with the previously set
 * key.
 *    If no key has already been set, passing NULL will lead into an undefined
 * behavior.
 *
 * @param  [in] key_len     hmac key length
 *    The key length shall be less than 64 bytes
 *
 * @return 1 if success, 0 if error
 */
int bls_hmac_ripemd160_init(bls_hmac_ripemd160_t *hmac, const uint8_t WIDE *key,
                            size_t key_len);

/**
 * @brief Initialize a HMAC sha256 context.
 *
 * @param [out] hmac        the context to init.
 *    The context shall be in RAM
 *
 * @param [in] key         hmac key value
 *    Passing a NULL pointeur, will reinit the context with the previously set
 * key.
 *    If no key has already been set, passing NULL will lead into an undefined
 * behavior.
 *
 * @param [in] key_len     hmac key length
 *    The key length shall be less than 64 bytes
 *
 * @return 1 if success, 0 if error
 */
int bls_hmac_sha256_init(bls_hmac_sha256_t *hmac, const uint8_t WIDE *key,
                         size_t key_len);

/**
 * @brief Initialize a HMAC sha512 context.
 *
 * @param [out] hmac       the context to init.
 *    The context shall be in RAM
 *
 * @param [in] key         hmac key value
 *    Passing a NULL pointeur, will reinit the context with the previously set
 * key.
 *    If no key has already been set, passing NULL will lead into an undefined
 * behavior.
 *
 * @param [in] key_len     hmac key length
 *    The key length shall be less than 128 bytes
 *
 * @return 1 if success, 0 if error
 */
int bls_hmac_sha512_init(bls_hmac_sha512_t *hmac, const uint8_t WIDE *key,
                         size_t key_len);

/**
 * @brief Add more data to HMAC
 *
 * @param [in,out] hmac
 *   Hmac context
 *   The hmac context pointer shall point to  either a bls_ripemd160_t, either a
 * bls_sha256_t  or bls_sha512_t .
 *   The hmac context shall be inited with 'bls_xxx_init'
 *   The hmac context shall be in RAM
 *   The function should be called with a nice cast.
 *
 * @param [in] mode
 *   16bits flags. See Above
 *   If BLS_LAST is set and BLS_DISCARD is not set, context is automatically
 * re-inited.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_DISCARD
 *
 * @param [in] in
 *   Input data to add to current hmac
 *
 * @param [in] len
 *   Length of input to data.
 *
 * @param [out] mac
 *   Either:
 *     - NULL (ignored) if BLS_LAST is NOT set
 *     - produced hmac  if BLS_LAST is set
 *   'out' length is implicit, no check is done
 *
 * @return 1 if success, not finished. Hmac size if success, finished. 0 if
 * error
 */
int bls_hmac(bls_hmac_t *hmac, int mode, const uint8_t WIDE *in, size_t len,
             uint8_t *mac);

/* ####################################################################### */
/*                             KEY STRETCHING                              */
/* ####################################################################### */

/**
 * @brief Stretch a password using PBKDF2
 *
 * @param [in] hash
 *   Hash Algorithm
 *   Supported algorithms : BLS_SHA512
 *
 * @param [in] password
 *   Password buffer and length
 *
 * @param [in] salt
 *   Salt buffer and length
*   The salt buffer shall include 4 extra pdding bytes
 *
 * @param [in] iterations
 *   Number of PBKDF2 iterations to perform
 *
 * @param [out] out
 *   Output buffer containing the PBKDF2 streched password
 *   The output buffer shall be as long as the hash output
 *
 * @return 1 if success, 0 if error
 */

int bls_pbkdf2(bls_md_t hash, const bls_area_t *password,
               const bls_area_t *salt, int iterations, uint8_t *out);

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

/**
 * @brief Initialize a DES Key.
 *
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any DES processing
 *
 * @param [in] rawkey
 *   raw key value
 *
 * @param [in] key_len
 *   key bytes length: 8,16 or 24
 *
 * @param [out] key
 *   DES key to init
 *
 * @param key
 *   ready to use key to init
 *
 * @return 1 if success, 0 if error
 */
int bls_des_init_key(const uint8_t WIDE *rawkey, size_t key_len,
                     bls_des_key_t *key);

/**
 * @brief Add data to a DES operation
 *
 * @param [in] key
 *   A des key fully inited with 'bls_des_init_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *     - BLS_SIGN
 *     - BLS_VERIFY
 *     - BLS_PAD_NONE
 *     - BLS_PAD_ISO9797M1
 *     - BLS_PAD_ISO9797M2
 *     - BLS_CHAIN_ECB
 *     - BLS_CHAIN_CBC
 *
 * @param [in] in
 *   Input data to encrypt/decrypt and associated length
 *   If BLS_LAST is set, padding is automatically done according to  'mode'.
 *   Else  'len' shall be a multiple of DES_BLOCK_SIZE.
 *
 * @param [out] out
 *   Either:
 *     - encrypted/decrypted ouput data
 *     - produced signature
 *     - signature to check
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT or SIGN mode: output length data
 *   - In case of VERIFY mode: 0 if signature is false, DES_BLOCK_SIZE if
 * signature is correct
 *
 * @throws INVALID_PARAMETER
 */
int bls_des(bls_des_key_t WIDE *key, int mode, const bls_area_t *in,
            bls_area_t *out);

/**
 * @brief Add data to a DES operation using an Initialization Vector
 *
 * @param [in] key
 *   A des key fully inited with 'bls_des_init_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *     - BLS_SIGN
 *     - BLS_VERIFY
 *     - BLS_PAD_NONE
 *     - BLS_PAD_ISO9797M1
 *     - BLS_PAD_ISO9797M2
 *     - BLS_CHAIN_ECB
 *     - BLS_CHAIN_CBC
 *
 *
 * @param [in] iv
 *   Initialization Vector and associated length
 *   Only meaningful for the first block of a BLS_CHAIN_CBC chaining.
 *   'len' shall be a multiple of DES_BLOCK_SIZE.
 *
 * @param [in] in
 *   Input data to encrypt/decrypt and associated length
 *   If BLS_LAST is set, padding is automatically done according to  'mode'.
 *   Else  'len' shall be a multiple of DES_BLOCK_SIZE.
 *
 * @param [out] out
 *   Either:
 *     - encrypted/decrypted ouput data
 *     - produced signature
 *     - signature to check
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT or SIGN mode: output length data
 *   - In case of VERIFY mode: 0 if signature is false, DES_BLOCK_SIZE if
 * signature is correct
 *
 * @throws INVALID_PARAMETER
 */
int bls_des_iv(bls_des_key_t WIDE *key, int mode, const bls_area_t *iv,
               const bls_area_t *in, bls_area_t *out);

/* ======================================================================= */
/*                                   AES                                   */
/* ======================================================================= */

/**
 * @brief Initialize an AES Key.
 *
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any AES processing
 *
 * @param [in] rawkey
 *   raw key value
 *
 * @param [in] key_len
 *   key bytes length: 16 or 32
 *
 * @param [out] key
 *   AES key to init
 *
 * @param key
 *   ready to use key to init
 *
 * @return 1 if success, 0 if error
 */
int bls_aes_init_key(const uint8_t WIDE *rawkey, size_t key_len,
                     bls_aes_key_t *key);

/**
 * @brief Add data to an AES operation
 *
 * @param [in] key
 *   A aes key fully inited with 'bls_aes_init_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *     - BLS_SIGN
 *     - BLS_VERIFY
 *     - BLS_PAD_NONE
 *     - BLS_PAD_ISO9797M1
 *     - BLS_PAD_ISO9797M2
 *     - BLS_CHAIN_ECB
 *     - BLS_CHAIN_CBC
 *     - BLS_AES_PAD_CTR
 *     - BLS_AES_PAD_CFB
 *     - BLS_AES_PAD_OFB
 *
 * @param [in] in
 *   Input data to encrypt/decrypt and associated length
 *   If BLS_LAST is set, padding is automtically done according to  'mode'.
 *   Else  'len' shall be a multiple of AES_BLOCK_SIZE.
 *
 * @param [out] out
 *   Either:
 *     - encrypted/decrypted ouput data
 *     - produced signature
 *     - signature to check
 *   'out' buffer length is implicit, no check is done
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT or SIGN mode: output length data
 *   - In case of VERIFY mode: 0 if signature is false, AES_BLOCK_SIZE if
 * signature is correct
 *
 * @throws INVALID_PARAMETER
 */
int bls_aes(bls_aes_key_t WIDE *key, int mode, const bls_area_t *in,
            bls_area_t *out);

/**
 * @brief Add data to an AES operation using an Initialization Vector
 *
 * @param [in] key
 *   A aes key fully inited with 'bls_aes_init_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *     - BLS_SIGN
 *     - BLS_VERIFY
 *     - BLS_PAD_NONE
 *     - BLS_PAD_ISO9797M1
 *     - BLS_PAD_ISO9797M2
 *     - BLS_CHAIN_ECB
 *     - BLS_CHAIN_CBC
 *     - BLS_AES_PAD_CTR
 *     - BLS_AES_PAD_CFB
 *     - BLS_AES_PAD_OFB
 *
  * @param [in] iv
 *   Initialization Vector and associated length
 *   Only meaningful for the first block of a BLS_CHAIN_CBC, BLS_AES_PAD_CTR,
 * BLS_AES_PAD_CFB, BLS_AES_PAD_OFB chaining.
 *   'len' shall be a multiple of DES_BLOCK_SIZE.
 *
 * @param [in] in
 *   Input data to encrypt/decrypt and associated length
 *   If BLS_LAST is set, padding is automtically done according to  'mode'.
 *   Else  'len' shall be a multiple of AES_BLOCK_SIZE.
 *
 * @param [out] out
 *   Either:
 *     - encrypted/decrypted ouput data
 *     - produced signature
 *     - signature to check
 *   'out' buffer length is implicit, no check is done
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT or SIGN mode: output length data
 *   - In case of VERIFY mode: 0 if signature is false, AES_BLOCK_SIZE if
 * signature is correct
 *
 * @throws INVALID_PARAMETER
 */
int bls_aes_iv(bls_aes_key_t WIDE *key, int mode, const bls_area_t *iv,
               const bls_area_t *in, bls_area_t *out);

/**
 * @brief Add data to an AES GCM operation
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param [in] key
 *   A aes key fully inited with 'bls_aes_init_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *
 * @param [in] in
 *   Input data to encrypt/decrypt and associated length
 *   If BLS_LAST is set, padding is automtically done according to  'mode'.
 *   Else  'len' shall be a multiple of AES_BLOCK_SIZE.
 *
 * @param [in] iv
 *   Initialization Vector and associated length
 *   'len' shall be a multiple of DES_BLOCK_SIZE.
 *
 * @param [in,out] aadTag
 *   - In case of ENCRYPT mode : AAD in, tag out
 *   - In case of DECRYPT mode : tag in
 *
 * @param [out] out
 *   Either:
 *     - encrypted/decrypted ouput data
 *   'out' buffer length is implicit, no check is done
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT : output length data
 *
 * @throws INVALID_PARAMETER
 */
int bls_aes_iv_gcm(bls_aes_key_t WIDE *key, int mode, const bls_area_t *in,
                   const bls_area_t *iv,
                   const bls_area_t WIDE
                       *aadTag, // encrypt : aad in/tag out | decrypt : tag in
                   bls_area_t *out);

/* ======================================================================= */
/*                                   RSA                                   */
/* ======================================================================= */

/**
 * @brief Initialize a public RSA Key.
 *
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any RSA processing
 * Passing NULL as raw key initializes the key without value. The key can not be
 * used
 *
 * @param [in] keyData
 *   Key parameters value or NULL.
 *   Key parameters shall include the modulus and public exponent encoded as big
 * endian raw value
 *
 * @param [out] key
 *   Public RSA key to initialize.
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_init_public_key(const bls_rsa_keypair_data_t WIDE *keyData,
                            bls_rsa_abstract_public_key_t *key);

/**
 * @brief Initialize a private RSA Key.
 *
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any RSA processing
 * Passing NULL as raw key initializes the key without value. The key can not be
 * used
 *
 * @param [in] keyData
 *   Key parameters value or NULL.
 *   Key parameters shall include the modulus and private exponent encoded as
 * big endian raw value
 *
 * @param [out] key
 *   Private RSA key to initialize.
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_init_private_key(const bls_rsa_keypair_data_t WIDE *keyData,
                             bls_rsa_abstract_private_key_t *key);

/**
 * @brief Initialize a private RSA Key with CRT parameters
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any RSA processing
 * Passing NULL as raw key initializes the key without value. The key can not be
 * used
 *
 * @param [in] keyData
 *   Key parameters value or NULL.
 *   Key parameters shall include Q, P, DP, DQ, QInv encoded as big endian raw
 * value
 *
 * @param [out] key
 *   Public RSA key to initialize.
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_init_private_key_crt(const bls_rsa_crt_t WIDE *crtParameters,
                                 bls_rsa_abstract_private_key_t *key);

/**
 * @brief Generate a RSA keypair
 *
 * @param [in] modulus_len
 *   Length of the modulus to generate, in bits
 *
 * @param [out] privateKey
 *   Pointer to a previously initialized RSA private key
 *
 * @param [out] publicKey
 *   Pointer to a previously initialized RSA public key
 *
 * @param [out] generatedKeypairInfo
 *   Pointer to a structure that will contain the generated key information
 *   including the private key value or NULL
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_generate_keypair(int modulus_len, // in bits
                             bls_rsa_abstract_private_key_t *privateKey,
                             bls_rsa_abstract_public_key_t *publicKey,
                             bls_rsa_keypair_data_t *generatedKeypairInfo);

/**
 * @brief Retrieve a RSA public key information
 *
 * @param [in] publicKey
 *   Pointer to a previously initialized RSA public key
 *
 * @param [out] keyInfo
 *   Pointer to a structure that will contain the public key information
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_get_public_key_data(bls_rsa_abstract_public_key_t *publicKey,
                                bls_rsa_keypair_data_t *keyInfo);

/**
 * @brief Perform a RSA public operation
 *
 * @param [in] key
 *   Pointer to a previously initialized RSA public key
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *     - BLS_PAD_NONE
 *     - BLS_PAD_PKCS1_1o5
 *     - BLS_PAD_PSS
 *
 * @param [in] hashID
 *  Hash identifier used to compute the input data.
 *
 * @param [in] src
 *   Input buffer and length to process
 *
 * @param [in,out] dest
 *   Destination buffer and length. Length is modified by ENCRYPT, DECRYPT, SIGN
 * operations
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT or SIGN mode: 1 if success, 0 if error
 *   - In case of VERIFY mode: 0 if signature is false, 1 if signature is
 * correct
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_pub(bls_rsa_abstract_public_key_t WIDE *key, int mode,
                bls_md_t hashID, const bls_area_t *src, const bls_area_t *dest);

/**
 * @brief Perform a RSA private operation
 *
 * @param [in] key
 *   Pointer to a previously initialized RSA private key
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_ENCRYPT
 *     - BLS_DECRYPT
 *     - BLS_PAD_NONE
 *     - BLS_PAD_PKCS1_1o5
 *     - BLS_PAD_PSS
 *
 * @param [in] hashID
 *  Hash identifier used to compute the input data.
 *
 * @param [in] src
 *   Input buffer and length to process
 *
 * @param [in,out] dest
 *   Destination buffer and length. Length is modified by ENCRYPT, DECRYPT, SIGN
 * operations
 *
 * @return
 *   - In case of ENCRYPT, DECRYPT or SIGN mode: 1 if success, 0 if error
 *   - In case of VERIFY mode: 0 if signature is false, 1 if signature is
 * correct
 *
 * @throws INVALID_PARAMETER
 */
int bls_rsa_priv(bls_rsa_abstract_private_key_t WIDE *key, int mode,
                 bls_md_t hashID, const bls_area_t *src,
                 const bls_area_t *dest);

/* ======================================================================= */
/*                                   ECDSA                                 */
/* ======================================================================= */

/**
 * @brief Retrieve the domain of the curve
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param [in] curve
 *   The curve reference
 *
 * @return
 *    The curve domain
 *
 * @throws INVALID_PARAMETER
 */
bls_curve_domain_t WIDE *bls_ecfp_get_domain(bls_curve_t curve);

/**
 * @brief Verify that a given point is really on the specified curve.
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param [in] domain
 *   The curve domain parameters to work with.
 *
 * @param [in]  point
 *   The point to test  encoded as: 04 x y
 *
 * @return
 *    1 if point is on the curve
 *    0 if point is not on the curve
 *   -1 if undefined (function not implemented)
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecfp_is_valid_point(const bls_curve_domain_t WIDE *domain,
                            const uint8_t WIDE *point);

/**
 * @brief Add two affine point
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param [in] domain
 *   The curve domain parameters to work with.
 *
 * @param [out] R
 *   P+Q encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] P
 *   First point to add *
 *   The value shall be a point encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] Q
 *   Second point to add
 *
 * @param [in]  public_point
 *   The point to test  encoded as: 04 x y
 *
 * @return
 *   R encoding length, if add success
 *   -1 if failed
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecfp_add_point(const bls_curve_domain_t WIDE *domain, uint8_t *R,
                       const uint8_t WIDE *P, const uint8_t WIDE *Q);

/**
 * @brief Initialize a public ECFP Key.
 *
 * Once initialized, the key may be stored in non-volatile memory
 * an reused 'as-is' for any ECDSA processing
 * Passing NULL as raw key initializes the key without value. The key may be
 used
 * as parameter for bls_ecfp_generate_pair.

 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [in] rawkey
 *   Raw key value or NULL.
 *   The value shall be the public point encoded as: 04 x y, where x and y are
 *   encoded as  big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [in] key_len
 *   Key bytes length
 *
 * @param [out] key
 *   Public ecfp key to init.
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecdsa_init_public_key(bls_curve_t curve, const uint8_t WIDE *rawkey,
                              size_t key_len, bls_ecfp_public_key_t *key);

/**
 * @brief Initialize a private ECFP Key.
 *
 * Once initialized, the key may be stored in non-volatile memory
 * and reused 'as-is' for any ECDSA processing
 * Passing NULL as raw key initializes the key without value. The key may be
 * used
 * as parameter for bls_ecfp_generate_pair.
 *
 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [in] rawkey
 *   Raw key value or NULL.
 *   The value shall be the private key big endian raw value.
 *
 * @param [in] key_len
 *   Key bytes length
 *
 * @param [out] key
 *   Private ecfp key to init.
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecdsa_init_private_key(bls_curve_t curve, const uint8_t WIDE *rawkey,
                               size_t key_len, bls_ecfp_private_key_t *key);
/**
 * @brief Generate a ecfp key pair
 *
 * @param [in] curve
 *   The curve domain parameters to work with.
 *
 * @param [out] public_key
 *   A public ecfp key to generate.
 *
 * @param [out] private_key
 *   A private ecfp key to initialize.
 *
 * @param [out] d
 *   If set to non NULL, return the generated private key value
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecfp_generate_pair(bls_curve_t curve, bls_ecfp_public_key_t *public_key,
                           bls_ecfp_private_key_t *private_key, uint8_t *d);

/**
 * @brief Return the uncompressed point of a public ECFP Key.
 *
 * @param [out] public_key
 *   A public ecfp key
 *
 * @param [out] W
 *   Buffer to store uncompressed point
 *
 * @return 1 if success, 0 if error
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecfp_get_public_component(const bls_ecfp_public_key_t *public_key,
                                  uint8_t *W);

/**
 * @brief Sign a hash message according to ECDSA scheme.
 *
 * @param [in] key
 *   A private ecfp key fully inited with 'bls_ecdsa_init_private_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *     - BLS_RND_TRNG
 *     - BLS_RND_RFC6979
 *
 * @param [in] hashID
 *  Hash to use for nonce generation when using BLS_RND_RFC6979 (shall be
 * BLS_SHA256)
 *
 * @param [in] hash
 *   Input data to sign.
 *   The data should be the hash of the original message.
 *   The data length must be lesser than the curve size.
 *
 * @param [in] hash_len
 *   Length of the hash
 *
 * @param [out] sig
 *   ECDSA signature encoded as TLV:  30 L 02 Lr r 02 Ls s
 *
 * @return
 *   Full length of signature
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecdsa_sign(bls_ecfp_private_key_t WIDE *key, int mode, bls_md_t hashID,
                   const uint8_t WIDE *hash, size_t hash_len, uint8_t *sig);
/**
 * @brief Verify a hash message signature according to ECDSA scheme.
 *
 * @param [in] key
 *   A public ecfp key fully inited with 'bls_ecdsa_init_public_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *
 * @param [in] hashID
 *  Ignored
 *
 * @param [in] hash
 *   Signed input data to verify the signature.
 *   The data should be the hash of the original message.
 *   The data length must be lesser than the curve size.
 *
 * @param [in] hash_len
 *   Length of the hash
 *
 * @param [in] sig
 *   ECDSA signature to verify encoded as TLV:  30 L 02 Lr r 02 Ls s
 *
 * @return
 *   1 if signature is verified
 *   0 is signarure is not verified
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecdsa_verify(bls_ecfp_public_key_t WIDE *key, int mode, bls_md_t hashID,
                     const uint8_t WIDE *hash, size_t hash_len, uint8_t *sig);

/**
 * @brief Sign a hash message according to Schnorr scheme
 *
 * @param [in] key
 *   A private ecfp key fully inited with 'bls_ecdsa_init_private_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *
 * @param [in] hashID
 *    Ignored
 *
 * @param [in] hash
 *   Input data to sign.
 *   The data should be the hash of the original message.
 *   The data length must be lesser than the curve size.
 *
 * @param [in] hash_len
 *   Length of the hash
 *
 * @param [out] sig
 *   Schnorr signature
 *
 * @return
 *   Full length of signature
 *
 * @throws INVALID_PARAMETER
 */
int bls_schnorr_sign(bls_ecfp_private_key_t WIDE *key, int mode,
                     bls_md_t hashID, const uint8_t WIDE *hash, size_t hash_len,
                     uint8_t *sig);
/**
 * @brief Verify a hash message signature according to Schnorr scheme.
 *
 * @param [in] key
 *   A public ecfp key fully inited with 'bls_ecdsa_init_public_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_LAST
 *
 * @param [in] hashID
 *  Ignored
 *
 * @param [in] hash
 *   Signed input data to verify the signature.
 *   The data should be the hash of the original message.
 *   The data length must be lesser than the curve size.
 *
 * @param [in] hash_len
 *   Length of the hash
 *
 * @param [in] sig
 *   Schnorr signature
 *
 * @return
 *   1 if signature is verified
 *   0 is signarure is not verified
 *
 * @throws INVALID_PARAMETER
 */
int bls_schnorr_verify(bls_ecfp_public_key_t WIDE *key, int mode,
                       bls_md_t hashID, const uint8_t WIDE *hash,
                       size_t hash_len, uint8_t *sig);

/* ======================================================================= */
/*                                     ECDH                                */
/* ======================================================================= */

/**
 * @brief Compute a shared secret according to ECDH specifiaction
 *
 * Depending on the mode, the shared secret is either the full point,
 * a hash of the x coordinate or only the x coordinate
 *
 * @param [in] key
 *   A private ecfp key fully inited with 'bls_ecdsa_init_private_key'
 *
 * @param [in] mode
 *   16bits crypto mode flags. See above.
 *   Supported flags:
 *     - BLS_ECDH_POINT
 *     - BLS_ECDH_X
 *     - BLS_ECDH_HASHED
 *
 * @param [in] public_point
 *   Other party public point encoded as: 04 x y, where x and y are
 *   encoded as big endian raw value and have bits length equals to
 *   the curve size.
 *
 * @param [out] secret
 *   Generated shared secret.
 *
 * @return size of secret
 *
 * @throws INVALID_PARAMETER
 */
int bls_ecdh(bls_ecfp_private_key_t WIDE *key, int mode,
             const uint8_t WIDE *public_point, uint8_t *secret);

/* ======================================================================= */
/*                                    CRC                                */
/* ======================================================================= */

/**
 * @brief Compute a 16 bits checksum value.
 *
 * The 16 bits value is computed according to the CRC16 CCITT definition.
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param [in] buffer
 *   The buffer to compute the crc over.
 *
 * @param [in]
 *   Bytes Length of the 'buffer'
 *
 * @return CRC value
 *
 */
uint16_t bls_crc16(const void WIDE *buffer, size_t len);

/**
 * @brief Update a 16 bits checksum value.
 *
 * The 16 bits value is computed according to the CRC16 CCITT definition.
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param [in] crc
 *   Initial CRC value
 *
 * @param [in] buffer
 *   The buffer to compute the crc over.
 *
 * @param [in]
 *   Bytes Length of the 'buffer'
 *
 * @return CRC value
 *
 */
uint16_t bls_crc16_update(unsigned short crc, const void WIDE *buffer,
                          size_t len);

/* ======================================================================= */
/*                                    MATH                                 */
/* ======================================================================= */

/**
 * @brief Modular addition of tow big integer of the size: r = a+b mod m
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * The maximum length supported is 64.
 *
 * @param r    where to put result
 * @param a    first operand
 * @param b    second operand
 * @param m    modulo
 * @param len  byte length of r, a, b, m
 *
 */
void bls_math_addm(uint8_t *r, const uint8_t WIDE *a, const uint8_t WIDE *b,
                   const uint8_t WIDE *m, size_t len);

/**
 * @brief Compare to unsigned long big-endian integer
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * The maximum length supported is 64.
 *
 * @param a    first operand
 * @param b    second operand
 * @param len  byte length of a, b
 *
 * @return 0 if a==b,  negative value if a<b, positive value if a>b
 */
int bls_math_cmp(const uint8_t WIDE *a, const uint8_t WIDE *b, size_t len);

/**
 * @brief Compare to unsigned long big-endian integer to zero
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param a    value to compare to zero
 * @param len  byte length of a
 *
 * @return 1 if a==0,  0 else
 */
int bls_math_is_zero(const uint8_t WIDE *a, size_t len);

/**
 * @brief Reduce in place (left zero padded) the given value : v = v mod m
 *
 * @warning THIS METHOD IS NOT SUPPORTED IN THE CURRENT RELEASE
 *
 * @param v        value to reduce
 * @param len_v    shall be >= len_m
 * @param m        modulus
 * @param len_m    length of modulus
 *
 */
void bls_math_modm(uint8_t *v, size_t len_v, const uint8_t WIDE *m,
                   size_t len_m);

#endif //__BOLOS_CRYPTO_H__
