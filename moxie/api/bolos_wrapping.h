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
 * @brief Bind data to a specific device, device session, and running
 * application
 * @file bolos_wrapping.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * The wrapping API allows executed code to exchange secret blobs with the
 * Normal World to be
 * consumed later.
 *
 * Blobs can have different lifetimes described in the wrapping scope below
 *
 * The lifetime of a session is defined by the lower level communication API
 *
 * The size of the metadata added by the wrapping operation is implementation
 * dependant
 */

#ifndef __BOLOS_WRAPPING_H__
#define __BOLOS_WRAPPING_H__

/**
 * @enum bls_wrapping_scope_e
 * @brief Describe the scope of the wrapped data
 */
enum bls_wrapping_scope_e {
    BLS_SCOPE_DEVICE,      /**< all applications can access on this device */
    BLS_SCOPE_APPLICATION, /**< only the creating application can access on this
                              device */
    BLS_SCOPE_SESSION, /**< all applications can access on this device for this
                          session */
    BLS_SCOPE_SESSION_APPLICATION, /**< only the creating application can access
                                      on this device for this session */
    BLS_SCOPE_PERSONALIZATION /**< can only unwrap a blob sent by the issuer
                                 server */
};
typedef enum bls_wrapping_scope_e bls_wrapping_scope_t;

/**
 * @brief Wrap data
 *
 * @param [in] scope
 *   Scope for which the data shall be wrapped
 *
 * @param [in] in
 *   Input buffer containing the data to wrap
 *
 * @param [in] length
 *   Length of the data to wrap
 *
 * @param [out] out
 *   Output buffer to contain the wrapped data
 *
 * @param [in] outLength
 *   Size of the output buffer containing the wrapped data
 *
 * @return size of the wrapped data
 *
 * @throws INVALID_PARAMETER
 */
unsigned int bls_wrap(bls_wrapping_scope_t scope, const uint8_t WIDE *in,
                      size_t length, uint8_t *out, size_t outLength);

/**
 * @brief Unwrap data
 *
 * @param [in] scope
 *   Scope for which the data had been wrapped
 *
 * @param [in] in
 *   Input buffer containing the data to unwrap
 *
 * @param [in] length
 *   Length of the data to unwrap
 *
 * @param [out] out
 *   Output buffer to contain the unwrapped data
 *
 * @param [in] outLength
 *   Size of the output buffer containing the unwrapped data
 *
 * @return size of the unwrapped data
 *
 * @throws INVALID_PARAMETER
 */
unsigned int bls_unwrap(bls_wrapping_scope_t scope, const uint8_t WIDE *in,
                        size_t length, uint8_t *out, size_t outLength);

#endif // __BOLOS_WRAPPING_H__
