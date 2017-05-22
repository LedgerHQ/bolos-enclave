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
 * @brief Endorsement API used to prove code execution on a secure device
 * @file bolos_endorsement.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * The endorsement API let developers verify cryptographic proofs that the code
 * is running on a trusted
 * device initialized by the issuer
 *
 * Two set of algorithms are available :
 *    - Algorithm 1 provides a secret to the running code, and let the running
 * code sign a message.
 *      Both elements are bound to the running code and the unique per device
 * private key A1.
 *
 *    - Algorithm 2 let the running code sign a message using a key derived from
 * the unique per device
 *    private key A2
 *
 * The provisioning of both keys can be done by the developer or the issuer
 *
 */

#ifndef __BOLOS_ENDORSEMENT_H__
#define __BOLOS_ENDORSEMENT_H__

/**
 * @enum bls_endorsement_key_e
 * @brief Describe the endorsement key to use
 */
enum bls_endorsement_key_e {
    BLS_ENDORSEMENT_KEY1, /**< use endorsement key 1 */
    BLS_ENDORSEMENT_KEY2  /**< use endorsement key 2 */
};
typedef enum bls_endorsement_key_e bls_endorsement_key_t;

/**
 * @brief Check if endorsement is supported for the given key
 *
 * @param [in] key
 *   Endorsement key to check
 *
 * @return 1 if supported, 0 if not supported
 */
int bls_endorsement_supported(bls_endorsement_key_t key);

/**
 * @brief Get the per device unique uncompressed public key signing the
 * endorsement initialization request
 *
 * @param [out] out
 *   Buffer to contain the key
 *
 * @param [in] outLength
 *   Size of the buffer to contain the key
 *
 * @return size of the uncompressed public key if success, 0 if error
 */
int bls_endorsement_get_authentication_public_key(uint8_t *out,
                                                  size_t outLength);

/**
 * @brief Initialize an endorsement key provisioning for the given key
 *
 * When called, the device generates a secp256k1 new key pair for the given
 * endorsement key
 * then returns the uncompressed public key and a signature of the uncompressed
 * public key by
 * the device unique endorsement authentication key.
 *
 * @param [in] key
 *   Endorsement key to provision
 *
 * @param [out] out
 *   Buffer to contain the endorsement provisioning request
 *
 * @param [in] outLength
 *   Size of the buffer to contain the endorsement provisioning request
 *
 * @return size of the endorsement provisioning request if success, 0 if error
 */
int bls_endorsement_init(bls_endorsement_key_t key, uint8_t *out,
                         size_t outLength);

/**
 * @brief Finalize an endorsement key provisioning process by providing the
 * associated certificate
 *
 * No check is performed on the certificate format
 *
 * @param [in] key
 *   Endorsement key to provision
 *
 * @param [in] response
 *   Buffer containing the certificate
 *
 * @param [in] responseLength
 *   Size of the buffer containing the certificate
 *
 * @return 1 if success, 0 if error
 */
int bls_endorsement_commit(bls_endorsement_key_t key, uint8_t *response,
                           size_t responseLength);

/**
 * @brief Get the currently running code hash
 *
 * The hashed data is implementation dependant
 *
 * @param [out] out
 *   Buffer to contain the hash
 *
 * @param [in] outLength
 *   Size of the buffer to contain the hash
 *
 * @return size of the code hash if success, 0 if error
 */
int bls_endorsement_get_code_hash(uint8_t *out, size_t outLength);

/**
 * @brief Get the application secret for endorsement key 1
 *
 * The application secret is defined as a HMAC-SHA512 of the currently running
 * code hash using the
 * endorsement key 1 as key
 *
 * @param [out] out
 *   Buffer to contain the application secret
 *
 * @param [in] outLength
 *   Size of the buffer to contain the application secret
 *
 * @return size of the application secret if success, 0 if error
 */
int bls_endorsement_key1_get_app_secret(uint8_t *out, size_t outLength);

/**
 * @brief Sign a message using endorsement key 1
 *
 * This call returns the ECDSA signature of a SHA-256 hash of (message ||
 * currently running code hash)
 * by endorsement key 1
 *
 * @param [in] in
 *   Buffer containing the message to sign
 *
 * @param [in] length
 *   Size of the message to sign
 *
 * @param [out] out
 *   Buffer to contain the signature
 *
 * @param [in] outLength
 *   Size of the buffer to contain the signature
 *
 * @return size of the signature if success, 0 if error
 */
int bls_endorsement_key1_sign_data(const uint8_t WIDE *in, size_t length,
                                   uint8_t *out, size_t outLength);

/**
 * @brief Sign a message using a key derived from endorsement key 2
 *
 * This call returns the ECDSA signature of a SHA-256 hash of the message
 * by a private key computed by adding mod n the HMAC-SHA256 of the endorsement
 * key 2 public key
 * using the currently running code hash as key to the endorsement key 2 private
 * key.
 *
 * @param [in] in
 *   Buffer containing the message to sign
 *
 * @param [in] length
 *   Size of the message to sign
 *
 * @param [out] out
 *   Buffer to contain the signature
 *
 * @param [in] outLength
 *   Size of the buffer to contain the signature
 *
 * @return size of the signature if success, 0 if error
 */
int bls_endorsement_key2_derive_sign_data(const uint8_t WIDE *in, size_t length,
                                          uint8_t *out, size_t outLength);

/**
 * @brief Get the public component of an endorsement key
 *
 * @param [in] endorsementKey
 *   Endorsement public key to retrieve
 *
 * @param [out] out
 *   Buffer to contain the uncompressed public key
 *
 * @param [in] outLength
 *   Size of the buffer to contain the uncompressed public key
 *
 * @return size of the uncompressed public key if success, 0 if error
 */
int bls_endorsement_get_public_key(bls_endorsement_key_t endorsementKey,
                                   uint8_t *out, size_t outLength);

/**
 * @brief Get the certificate associated to an endorsement key
 *
 * @param [in] endorsementKey
 *   Endorsement certificate to retrieve
 *
 * @param [out] out
 *   Buffer to contain the certificate
 *
 * @param [in] outLength
 *   Size of the buffer to contain the certificate
 *
 * @return size of the certificate if success, 0 if error
 */
int bls_endorsement_get_certificate(bls_endorsement_key_t endorsementKey,
                                    uint8_t *out, size_t outLength);

#endif // __BOLOS_ENDORSEMENT_H__
