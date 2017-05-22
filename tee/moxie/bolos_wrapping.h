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

#ifndef __BOLOS_WRAPPING_H__
#define __BOLOS_WRAPPING_H__

enum bls_wrapping_scope_e {
    BLS_SCOPE_DEVICE,      // all applications can access on this device
    BLS_SCOPE_APPLICATION, // only the creating application can access on this
                           // device
    BLS_SCOPE_SESSION, // all applications can access on this device for this
                       // session
    BLS_SCOPE_SESSION_APPLICATION, // only the creating application can access
                                   // on this device for this session
    BLS_SCOPE_PERSONALIZATION      // can only unwrap
};
typedef enum bls_wrapping_scope_e bls_wrapping_scope_t;

unsigned int bls_wrap(bls_wrapping_scope_t scope, const uint8_t WIDE *in,
                      size_t length, uint8_t *out, size_t outLength);

unsigned int bls_unwrap(bls_wrapping_scope_t scope, const uint8_t WIDE *in,
                        size_t length, uint8_t *out, size_t outLength);

#endif // __BOLOS_WRAPPING_H__
