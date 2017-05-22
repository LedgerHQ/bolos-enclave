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
 * @brief Interface to the main Bitcoin Wallet provided to third party
 * applications
 * @file bolos_wallet.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Using this API third party applications can interact with the Bitcoin Wallet
 * or
 * common provisioned secrets without revealing them
 *
 * This API is only available if the TEE exposes a Bitcoin Wallet to the user
 *
 */

#ifndef __BOLOS_WALLET_H__
#define __BOLOS_WALLET_H__

/** Bitcoin wallet is initialized */
#define BLS_WALLET_STATE_INITIALIZED (1 << 0)
/** Bitcoin wallet is locked */
#define BLS_WALLET_STATE_LOCKED (1 << 1)
/** Bitcoin wallet can be unlocked by the application */
#define BLS_WALLET_UNLOCK_INAPP (1 << 2)

/** Perform a BIP 32 private derivation */
#define BLS_WALLET_DERIVE_PRIVATE (1 << 0)
/** Perform a BIP 32 public derivation */
#define BLS_WALLET_DERIVE_PUBLIC (1 << 1)

/**
 * @brief Return the current state of the Bitcoin wallet
 *
 * @return state of the wallet
 */
int bls_wallet_get_state(void);

/**
 * @brief Derive a Bitcoin wallet key using BIP 32
 *
 * @param [in] details
 *   Derivation method, either BLS_WALLET_DERIVE_PUBLIC or
 * BLS_WALLET_DERIVE_PRIVATE
 *
 * @param [in] path
 *   BIP 32 derivation path encoded as an array of big endian integers
 *
 * @param [in] pathLength
 *   Number of nodes in the provided BIP 32 derivation path
 *
 * @param [out] chainCode
 *   Buffer to contain the chain code or NULL
 *
 * @param [out] privateKey
 *   Pointer to a previously initialized private key to store the derived
 * private key
 *
 * @param [out] publicKey
 *   Pointer to a previously initialized public key to store the derived public
 * key
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_wallet_derive(uint8_t details, const uint32_t WIDE *path,
                      size_t pathLength, uint8_t *chainCode,
                      bls_ecfp_private_key_t *privateKey,
                      bls_ecfp_public_key_t *publicKey);

/**
 * @brief Get the Bitcoin address associated to a given public key
 *
 * @warning In the current API release, the version of the wallet application is
 * used for the address version.
 * This API will be deprecated.
 *
 * @param [in] publicKey
 *   Previously initialized Public Key
 *
 * @param [out] address
 *   Buffer to contain the generated address
 *
 * @param [in] addressLength
 *   Size of the buffer to contain the generated address
 *
 * @param [in] compressed
 *   Compute the address for a compressed key if set to true, otherwise compute
 * it for an uncompressed key
 *
 * @return address length if success, 0 if error
 *
 */
int bls_wallet_get_address(bls_ecfp_public_key_t *publicKey, char WIDE *address,
                           size_t addressLength, bool compressed);

/**
 * @brief Call the Ledger Wallet application
 *
 * This function call is specific to BOLOS TEE implementation
 * The Ledger Wallet application is called in a special mode where the Trusted
 * UI is disabled
 *
 * @param [in] apdu
 *   APDU buffer containing the command to send to the Ledger Wallet application
 *   This buffer is overwritten by the response
 *
 * @return size of the response data and 2 bytes Status Word if success, 0 if
 * error
 *
 */
int bls_wallet_call(uint8_t *apdu);

/**
 * @brief Approve a signature before calling the Ledger Wallet application
 *
 * This function call is specific to BOLOS TEE implementation
 *
 * @param [in] status
 *   true to approve the signature, false to reject it
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_wallet_approve_sign(bool status);

#endif // __BOLOS_WALLET_H__
