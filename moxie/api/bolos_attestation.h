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
 * @brief Legacy attestation logic compatible with Ledger Wallet
 * @file bolos_attestation.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * The legacy attestation logic let the client application verify that it is
 * communicating with an application
 * personalized with a given (set of) private keys.
 *
 * The attestation logic is deprecated by the endorsement API and only kept for
 * historical purposes
 *
 */

#ifndef __BOLOS_ATTESTATION_H__
#define __BOLOS_ATTESTATION_H__

/**
 * @brief Check if attestation is supported
 *
 * @return 1 if supported, 0 if not supported
 */
int bls_attestation_supported(void);

/**
 * @brief Sign a data blob using the attestation key
 *
 * @param [in] in
 *   Buffer containing the data to sign
 *
 * @param [in] length
 *   Length of thed data to sign
 *
 * @param [out] out
 *   Buffer to contain the signature
 *
 * @param [in] outLength
 *   Size of the buffer to contain the signature
 *
 * @return signature length if success, 0 if error
 *
 */
int bls_attestation_device_get_data_signature(const uint8_t WIDE *in,
                                              size_t length, uint8_t *out,
                                              size_t outLength);

#endif // __BOLOS_ATTESTATION_H__
