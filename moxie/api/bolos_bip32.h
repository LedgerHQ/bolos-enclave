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
 * @brief Interface to low level BIP 32 operations
 * @file bolos_bip32.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2017
 *
 * This API exposes simple BIP 32 derivation primitives
 *
 */

#ifndef __BOLOS_BIP32_H__
#define __BOLOS_BIP32_H__

/**
 * @brief Derive a private key on secp256k1 using BIP 32
 *
 * @param [in,out] privateKey
 *   Private key to derive
 *
 * @param [in,out] chainCode
 *   Chain code to derive
 *
 * @param [in] index
 *   Index to derive to
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_bip32_derive_secp256k1_private(uint8_t *privateKey, uint8_t *chainCode,
                                       uint32_t index);

/**
 * @brief Derive a compressed public key on secp256k1 using BIP 32
 *
 * @param [in,out] publicKey
 *   Compressed public key to derive
 *
 * @param [in,out] chainCode
 *   Chain code to derive
 *
 * @param [in] index
 *   Index to derive to
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_bip32_derive_secp256k1_public(uint8_t *publicKey, uint8_t *chainCode,
                                      uint32_t index);

#endif // __BOLOS_BIP32_H__
