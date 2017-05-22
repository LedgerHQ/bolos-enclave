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

#ifndef __BOLOS_ENDORSEMENT_H__
#define __BOLOS_ENDORSEMENT_H__

enum bls_endorsement_key_e { BLS_ENDORSEMENT_KEY1, BLS_ENDORSEMENT_KEY2 };
typedef enum bls_endorsement_key_e bls_endorsement_key_t;

int bls_endorsement_supported(void);

int bls_endorsement_init(bls_endorsement_key_t key, uint8_t *out,
                         size_t outLength);

int bls_endorsement_commit(bls_endorsement_key_t key, uint8_t *response,
                           size_t responseLength);

int bls_endorsement_get_code_hash(uint8_t *out, size_t outLength);

// HMAC(H(C), device_secret1)
int bls_endorsement_key1_get_app_secret(uint8_t *out, size_t outLength);

// Sign(device_secret1, H(H(C) || message))
int bls_endorsement_key1_sign_data(const uint8_t WIDE *in, size_t length,
                                   uint8_t *out, size_t outLength);

// key 2 is device_secret2 + HMAC(device_pubkey, H(C))
int bls_endorsement_key2_derive_sign_data(const uint8_t WIDE *in, size_t length,
                                          uint8_t *out, size_t outLength);

int bls_endorsement_get_public_key(bls_endorsement_key_t endorsementKey,
                                   uint8_t *out, size_t outLength);

int bls_endorsement_get_certificate(bls_endorsement_key_t endorsementKey,
                                    uint8_t *out, size_t outLength);

#endif // __BOLOS_ENDORSEMENT_H__
