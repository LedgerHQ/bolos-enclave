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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "machine.h"

/*
* bls_set_return
* $r0 -- addr void*
* $r1 -- length size_t
* Output:
* void
*/
void moxie_bls_set_return(struct machine *mach);

/*
* bls_get_input_parameters_length
* Output:
* size_t
*/
void moxie_bls_get_input_parameters_length(struct machine *mach);

/*
* bls_copy_input_parameters
* $r0 -- parameters uint8_t*
* $r1 -- offset uint32_t
* $r2 -- parametersLength size_t
* Output:
* size_t
*/
void moxie_bls_copy_input_parameters(struct machine *mach);

/*
* bls_check_api_level
* Output:
* uint32_t
*/
void moxie_bls_check_api_level(struct machine *mach);

/*
* _exit
* $r0 -- status uint32_t
* Output:
* void
*/
void moxie__exit(struct machine *mach);

/*
* bls_rng_u8
* Output:
* uint8_t
*/
void moxie_bls_rng_u8(struct machine *mach);

/*
* bls_rng
* $r0 -- buffer uint8_t*
* $r1 -- len size_t
* Output:
* int
*/
void moxie_bls_rng(struct machine *mach);

/*
* bls_ripemd160_init
* $r0 -- hash bls_ripemd160_t*
* Output:
* int
*/
void moxie_bls_ripemd160_init(struct machine *mach);

/*
* bls_sha1_init
* $r0 -- hash bls_sha1_t*
* Output:
* int
*/
void moxie_bls_sha1_init(struct machine *mach);

/*
* bls_sha256_init
* $r0 -- hash bls_sha256_t*
* Output:
* int
*/
void moxie_bls_sha256_init(struct machine *mach);

/*
* bls_sha512_init
* $r0 -- hash bls_sha512_t*
* Output:
* int
*/
void moxie_bls_sha512_init(struct machine *mach);

/*
* bls_sha3_init
* $r0 -- hash bls_sha3_t*
* $r1 -- size int
* Output:
* int
*/
void moxie_bls_sha3_init(struct machine *mach);

/*
* bls_keccak_init
* $r0 -- hash bls_sha3_t*
* $r1 -- size int
* Output:
* int
*/
void moxie_bls_keccak_init(struct machine *mach);

/*
* bls_hash
* $r0 -- hash bls_hash_t*
* $r1 -- mode int
* $r2 -- in uint8_t*
* $r3 -- len size_t
* $r4 -- out uint8_t*
* Output:
* int
*/
void moxie_bls_hash(struct machine *mach);

/*
* bls_hmac_ripemd160_init
* $r0 -- hmac bls_hmac_ripemd160_t*
* $r1 -- key uint8_t*
* $r2 -- key_len size_t
* Output:
* int
*/
void moxie_bls_hmac_ripemd160_init(struct machine *mach);

/*
* bls_hmac_sha256_init
* $r0 -- hmac bls_hmac_sha256_t*
* $r1 -- key uint8_t*
* $r2 -- key_len size_t
* Output:
* int
*/
void moxie_bls_hmac_sha256_init(struct machine *mach);

/*
* bls_hmac_sha512_init
* $r0 -- hmac bls_hmac_sha512_t*
* $r1 -- key uint8_t*
* $r2 -- key_len size_t
* Output:
* int
*/
void moxie_bls_hmac_sha512_init(struct machine *mach);

/*
* bls_hmac
* $r0 -- hmac bls_hmac_t*
* $r1 -- mode int
* $r2 -- in uint8_t*
* $r3 -- len size_t
* $r4 -- mac uint8_t*
* Output:
* int
*/
void moxie_bls_hmac(struct machine *mach);

/*
* bls_pbkdf2
* $r0 -- hash bls_md_t
* $r1 -- password bls_area_t*
* $r2 -- salt bls_area_t*
* $r3 -- iterations int
* $r4 -- out uint8_t*
* Output:
* int
*/
void moxie_bls_pbkdf2(struct machine *mach);

/*
* bls_des_init_key
* $r0 -- rawkey uint8_t*
* $r1 -- key_len size_t
* $r2 -- key bls_des_key_t*
* Output:
* int
*/
void moxie_bls_des_init_key(struct machine *mach);

/*
* bls_des
* $r0 -- key bls_des_key_t*
* $r1 -- mode int
* $r2 -- in bls_area_t*
* $r3 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_des(struct machine *mach);

/*
* bls_des_iv
* $r0 -- key bls_des_key_t*
* $r1 -- mode int
* $r2 -- iv bls_area_t*
* $r3 -- in bls_area_t*
* $r4 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_des_iv(struct machine *mach);

/*
* bls_aes_init_key
* $r0 -- rawkey uint8_t*
* $r1 -- key_len size_t
* $r2 -- key bls_aes_key_t*
* Output:
* int
*/
void moxie_bls_aes_init_key(struct machine *mach);

/*
* bls_aes
* $r0 -- key bls_aes_key_t*
* $r1 -- mode int
* $r2 -- in bls_area_t*
* $r3 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_aes(struct machine *mach);

/*
* bls_aes_iv
* $r0 -- key bls_aes_key_t*
* $r1 -- mode int
* $r2 -- iv bls_area_t*
* $r3 -- in bls_area_t*
* $r4 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_aes_iv(struct machine *mach);

/*
* bls_aes_iv_gcm
* $r0 -- key bls_aes_key_t*
* $r1 -- mode int
* $r2 -- in bls_area_t*
* $r3 -- iv bls_area_t*
* $r4 -- aadTag bls_area_t*
* $r5 -- out bls_area_t*
* Output:
* int
*/
void moxie_bls_aes_iv_gcm(struct machine *mach);

/*
* bls_rsa_init_public_key
* $r0 -- keyData bls_rsa_keypair_data_t*
* $r1 -- key bls_rsa_abstract_public_key_t*
* Output:
* int
*/
void moxie_bls_rsa_init_public_key(struct machine *mach);

/*
* bls_rsa_init_private_key
* $r0 -- keyData bls_rsa_keypair_data_t*
* $r1 -- key bls_rsa_abstract_private_key_t*
* Output:
* int
*/
void moxie_bls_rsa_init_private_key(struct machine *mach);

/*
* bls_rsa_init_private_key_crt
* $r0 -- crtParameters bls_rsa_crt_t*
* $r1 -- key bls_rsa_abstract_private_key_t*
* Output:
* int
*/
void moxie_bls_rsa_init_private_key_crt(struct machine *mach);

/*
* bls_rsa_generate_keypair
* $r0 -- modulus_len int
* $r1 -- privateKey bls_rsa_abstract_private_key_t*
* $r2 -- publicKey bls_rsa_abstract_public_key_t*
* $r3 -- generatedKeypairInfo bls_rsa_keypair_data_t*
* Output:
* int
*/
void moxie_bls_rsa_generate_keypair(struct machine *mach);

/*
* bls_rsa_get_public_key_data
* $r0 -- publicKey bls_rsa_abstract_public_key_t*
* $r1 -- keyInfo bls_rsa_keypair_data_t*
* Output:
* int
*/
void moxie_bls_rsa_get_public_key_data(struct machine *mach);

/*
* bls_rsa_pub
* $r0 -- key bls_rsa_abstract_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- src bls_area_t*
* $r4 -- dest bls_area_t*
* Output:
* int
*/
void moxie_bls_rsa_pub(struct machine *mach);

/*
* bls_rsa_priv
* $r0 -- key bls_rsa_abstract_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- src bls_area_t*
* $r4 -- dest bls_area_t*
* Output:
* int
*/
void moxie_bls_rsa_priv(struct machine *mach);

/*
* bls_ecfp_get_domain
* $r0 -- curve bls_curve_t
* Output:
* bls_curve_domain_t*
*/
void moxie_bls_ecfp_get_domain(struct machine *mach);

/*
* bls_ecfp_is_valid_point
* $r0 -- domain bls_curve_domain_t*
* $r1 -- point uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_is_valid_point(struct machine *mach);

/*
* bls_ecfp_add_point
* $r0 -- domain bls_curve_domain_t*
* $r1 -- R uint8_t*
* $r2 -- P uint8_t*
* $r3 -- Q uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_add_point(struct machine *mach);

/*
* bls_ecdsa_init_public_key
* $r0 -- curve bls_curve_t
* $r1 -- rawkey uint8_t*
* $r2 -- key_len size_t
* $r3 -- key bls_ecfp_public_key_t*
* Output:
* int
*/
void moxie_bls_ecdsa_init_public_key(struct machine *mach);

/*
* bls_ecdsa_init_private_key
* $r0 -- curve bls_curve_t
* $r1 -- rawkey uint8_t*
* $r2 -- key_len size_t
* $r3 -- key bls_ecfp_private_key_t*
* Output:
* int
*/
void moxie_bls_ecdsa_init_private_key(struct machine *mach);

/*
* bls_ecfp_generate_pair
* $r0 -- curve bls_curve_t
* $r1 -- public_key bls_ecfp_public_key_t*
* $r2 -- private_key bls_ecfp_private_key_t*
* $r3 -- d uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_generate_pair(struct machine *mach);

/*
* bls_ecfp_get_public_component
* $r0 -- public_key bls_ecfp_public_key_t*
* $r1 -- W uint8_t*
* Output:
* int
*/
void moxie_bls_ecfp_get_public_component(struct machine *mach);

/*
* bls_ecdsa_sign
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_ecdsa_sign(struct machine *mach);

/*
* bls_ecdsa_verify
* $r0 -- key bls_ecfp_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_ecdsa_verify(struct machine *mach);

/*
* bls_schnorr_sign
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_schnorr_sign(struct machine *mach);

/*
* bls_schnorr_verify
* $r0 -- key bls_ecfp_public_key_t*
* $r1 -- mode int
* $r2 -- hashID bls_md_t
* $r3 -- hash uint8_t*
* $r4 -- hash_len size_t
* $r5 -- sig uint8_t*
* Output:
* int
*/
void moxie_bls_schnorr_verify(struct machine *mach);

/*
* bls_ecdh
* $r0 -- key bls_ecfp_private_key_t*
* $r1 -- mode int
* $r2 -- public_point uint8_t*
* $r3 -- secret uint8_t*
* Output:
* int
*/
void moxie_bls_ecdh(struct machine *mach);

/*
* bls_crc16
* $r0 -- buffer void*
* $r1 -- len size_t
* Output:
* uint16_t
*/
void moxie_bls_crc16(struct machine *mach);

/*
* bls_crc16_update
* $r0 -- crc unsigned short
* $r1 -- buffer void*
* $r2 -- len size_t
* Output:
* uint16_t
*/
void moxie_bls_crc16_update(struct machine *mach);

/*
* bls_math_addm
* $r0 -- r uint8_t*
* $r1 -- a uint8_t*
* $r2 -- b uint8_t*
* $r3 -- m uint8_t*
* $r4 -- len size_t
* Output:
* void
*/
void moxie_bls_math_addm(struct machine *mach);

/*
* bls_math_cmp
* $r0 -- a uint8_t*
* $r1 -- b uint8_t*
* $r2 -- len size_t
* Output:
* int
*/
void moxie_bls_math_cmp(struct machine *mach);

/*
* bls_math_is_zero
* $r0 -- a uint8_t*
* $r1 -- len size_t
* Output:
* int
*/
void moxie_bls_math_is_zero(struct machine *mach);

/*
* bls_math_modm
* $r0 -- v uint8_t*
* $r1 -- len_v size_t
* $r2 -- m uint8_t*
* $r3 -- len_m size_t
* Output:
* void
*/
void moxie_bls_math_modm(struct machine *mach);

/*
* bls_wrap
* $r0 -- scope bls_wrapping_scope_t
* $r1 -- in uint8_t*
* $r2 -- length size_t
* $r3 -- out uint8_t*
* $r4 -- outLength size_t
* Output:
* unsigned int
*/
void moxie_bls_wrap(struct machine *mach);

/*
* bls_unwrap
* $r0 -- scope bls_wrapping_scope_t
* $r1 -- in uint8_t*
* $r2 -- length size_t
* $r3 -- out uint8_t*
* $r4 -- outLength size_t
* Output:
* unsigned int
*/
void moxie_bls_unwrap(struct machine *mach);

/*
* bls_attestation_supported
* Output:
* int
*/
void moxie_bls_attestation_supported(struct machine *mach);

/*
* bls_attestation_device_get_data_signature
* $r0 -- in uint8_t*
* $r1 -- length size_t
* $r2 -- out uint8_t*
* $r3 -- outLength size_t
* Output:
* int
*/
void moxie_bls_attestation_device_get_data_signature(struct machine *mach);

/*
* bls_endorsement_supported
* $r0 -- key bls_endorsement_key_t
* Output:
* int
*/
void moxie_bls_endorsement_supported(struct machine *mach);

/*
* bls_endorsement_get_authentication_public_key
* $r0 -- out uint8_t*
* $r1 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_authentication_public_key(struct machine *mach);

/*
* bls_endorsement_init
* $r0 -- key bls_endorsement_key_t
* $r1 -- out uint8_t*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_init(struct machine *mach);

/*
* bls_endorsement_commit
* $r0 -- key bls_endorsement_key_t
* $r1 -- response uint8_t*
* $r2 -- responseLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_commit(struct machine *mach);

/*
* bls_endorsement_get_code_hash
* $r0 -- out uint8_t*
* $r1 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_code_hash(struct machine *mach);

/*
* bls_endorsement_key1_get_app_secret
* $r0 -- out uint8_t*
* $r1 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_key1_get_app_secret(struct machine *mach);

/*
* bls_endorsement_key1_sign_data
* $r0 -- in uint8_t*
* $r1 -- length size_t
* $r2 -- out uint8_t*
* $r3 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_key1_sign_data(struct machine *mach);

/*
* bls_endorsement_key2_derive_sign_data
* $r0 -- in uint8_t*
* $r1 -- length size_t
* $r2 -- out uint8_t*
* $r3 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_key2_derive_sign_data(struct machine *mach);

/*
* bls_endorsement_get_public_key
* $r0 -- endorsementKey bls_endorsement_key_t
* $r1 -- out uint8_t*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_public_key(struct machine *mach);

/*
* bls_endorsement_get_certificate
* $r0 -- endorsementKey bls_endorsement_key_t
* $r1 -- out uint8_t*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_endorsement_get_certificate(struct machine *mach);

/*
* bls_antireplay_supported
* Output:
* int
*/
void moxie_bls_antireplay_supported(struct machine *mach);

/*
* bls_antireplay_create
* $r0 -- referenceOut uint8_t*
* $r1 -- referenceOutLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_create(struct machine *mach);

/*
* bls_antireplay_query
* $r0 -- reference uint8_t*
* $r1 -- referenceLength size_t
* $r2 -- value uint32_t*
* Output:
* int
*/
void moxie_bls_antireplay_query(struct machine *mach);

/*
* bls_antireplay_increase
* $r0 -- reference uint8_t*
* $r1 -- referenceLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_increase(struct machine *mach);

/*
* bls_antireplay_delete
* $r0 -- reference uint8_t*
* $r1 -- referenceLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_delete(struct machine *mach);

/*
* bls_sharedmemory_get_size
* Output:
* int
*/
void moxie_bls_sharedmemory_get_size(struct machine *mach);

/*
* bls_sharedmemory_read
* $r0 -- parameters uint8_t*
* $r1 -- offset uint32_t
* $r2 -- parametersLength size_t
* Output:
* size_t
*/
void moxie_bls_sharedmemory_read(struct machine *mach);

/*
* bls_sharedmemory_write
* $r0 -- parameters uint8_t*
* $r1 -- offset uint32_t
* $r2 -- parametersLength size_t
* Output:
* size_t
*/
void moxie_bls_sharedmemory_write(struct machine *mach);

/*
* bls_time_supported
* Output:
* int
*/
void moxie_bls_time_supported(struct machine *mach);

/*
* bls_time_delta
* $r0 -- referenceOut uint8_t*
* $r1 -- referenceOutLength size_t
* $r2 -- delta uint64_t*
* $r3 -- trusted uint8_t*
* Output:
* int
*/
void moxie_bls_time_delta(struct machine *mach);

/*
* bls_time
* $r0 -- time uint64_t*
* $r1 -- trusted uint8_t*
* Output:
* int
*/
void moxie_bls_time(struct machine *mach);

/*
* bls_continuation_supported
* Output:
* int
*/
void moxie_bls_continuation_supported(struct machine *mach);

/*
* bls_set_continuation
* $r0 -- addr void*
* $r1 -- length size_t
* Output:
* void
*/
void moxie_bls_set_continuation(struct machine *mach);

/*
* bls_debug
* $r0 -- text char*
* Output:
* void
*/
void moxie_bls_debug(struct machine *mach);

/*
* bls_bip32_derive_secp256k1_private
* $r0 -- privateKey uint8_t*
* $r1 -- chainCode uint8_t*
* $r2 -- index uint32_t
* Output:
* int
*/
void moxie_bls_bip32_derive_secp256k1_private(struct machine *mach);

/*
* bls_bip32_derive_secp256k1_public
* $r0 -- publicKey uint8_t*
* $r1 -- chainCode uint8_t*
* $r2 -- index uint32_t
* Output:
* int
*/
void moxie_bls_bip32_derive_secp256k1_public(struct machine *mach);

/*
* bls_wallet_get_state
* Output:
* int
*/
void moxie_bls_wallet_get_state(struct machine *mach);

/*
* bls_wallet_derive
* $r0 -- details uint8_t
* $r1 -- path uint32_t*
* $r2 -- pathLength size_t
* $r3 -- chainCode uint8_t*
* $r4 -- privateKey bls_ecfp_private_key_t*
* $r5 -- publicKey bls_ecfp_public_key_t*
* Output:
* int
*/
void moxie_bls_wallet_derive(struct machine *mach);

/*
* bls_wallet_get_address
* $r0 -- publicKey bls_ecfp_public_key_t*
* $r1 -- address char*
* $r2 -- addressLength size_t
* $r3 -- compressed bool
* Output:
* int
*/
void moxie_bls_wallet_get_address(struct machine *mach);

/*
* bls_wallet_call
* $r0 -- apdu uint8_t*
* Output:
* int
*/
void moxie_bls_wallet_call(struct machine *mach);

/*
* bls_wallet_approve_sign
* $r0 -- status bool
* Output:
* int
*/
void moxie_bls_wallet_approve_sign(struct machine *mach);

/*
* bls_ui_get_capabilities
* Output:
* int
*/
void moxie_bls_ui_get_capabilities(struct machine *mach);

/*
* bls_ui_display_message
* $r0 -- text char*
* Output:
* int
*/
void moxie_bls_ui_display_message(struct machine *mach);

/*
* bls_ui_display_warning
* $r0 -- text char*
* Output:
* int
*/
void moxie_bls_ui_display_warning(struct machine *mach);

/*
* bls_ui_display_error
* $r0 -- text char*
* Output:
* int
*/
void moxie_bls_ui_display_error(struct machine *mach);

/*
* bls_ui_display_choice
* $r0 -- message char*
* Output:
* int
*/
void moxie_bls_ui_display_choice(struct machine *mach);

/*
* bls_ui_display_qr
* $r0 -- message char*
* $r1 -- data char*
* $r2 -- dataSize size_t
* Output:
* int
*/
void moxie_bls_ui_display_qr(struct machine *mach);

/*
* bls_ui_get_user_entry
* $r0 -- message char*
* $r1 -- out char*
* $r2 -- outLength size_t
* Output:
* int
*/
void moxie_bls_ui_get_user_entry(struct machine *mach);

/*
* crypto_secretbox_easy
* $r0 -- c unsigned char*
* $r1 -- m unsigned char*
* $r2 -- mlen unsigned long
* $r3 -- n unsigned char*
* $r4 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_secretbox_easy(struct machine *mach);

/*
* crypto_secretbox_open_easy
* $r0 -- m unsigned char*
* $r1 -- c unsigned char*
* $r2 -- clen unsigned long
* $r3 -- n unsigned char*
* $r4 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_secretbox_open_easy(struct machine *mach);

/*
* crypto_auth
* $r0 -- out unsigned char*
* $r1 -- in unsigned char*
* $r2 -- inlen unsigned long
* $r3 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_auth(struct machine *mach);

/*
* crypto_auth_verify
* $r0 -- h unsigned char*
* $r1 -- in unsigned char*
* $r2 -- inlen unsigned long
* $r3 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_auth_verify(struct machine *mach);

/*
* crypto_box_keypair
* $r0 -- pk unsigned char*
* $r1 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_keypair(struct machine *mach);

/*
* crypto_box_easy
* $r0 -- c unsigned char*
* $r1 -- m unsigned char*
* $r2 -- mlen unsigned long
* $r3 -- n unsigned char*
* $r4 -- pk unsigned char*
* $r5 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_easy(struct machine *mach);

/*
* crypto_box_open_easy
* $r0 -- m unsigned char*
* $r1 -- c unsigned char*
* $r2 -- clen unsigned long
* $r3 -- n unsigned char*
* $r4 -- pk unsigned char*
* $r5 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_open_easy(struct machine *mach);

/*
* crypto_box_seal
* $r0 -- c unsigned char*
* $r1 -- m unsigned char*
* $r2 -- mlen unsigned long
* $r3 -- pk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_seal(struct machine *mach);

/*
* crypto_box_seal_open
* $r0 -- m unsigned char*
* $r1 -- c unsigned char*
* $r2 -- clen unsigned long
* $r3 -- pk unsigned char*
* $r4 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_seal_open(struct machine *mach);

/*
* crypto_sign_keypair
* $r0 -- pk unsigned char*
* $r1 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_sign_keypair(struct machine *mach);

/*
* crypto_sign
* $r0 -- sm unsigned char*
* $r1 -- smlen_p unsigned long*
* $r2 -- m unsigned char*
* $r3 -- mlen unsigned long
* $r4 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_sign(struct machine *mach);

/*
* crypto_sign_open
* $r0 -- m unsigned char*
* $r1 -- mlen_p unsigned long*
* $r2 -- sm unsigned char*
* $r3 -- smlen unsigned long
* $r4 -- pk unsigned char*
* Output:
* int
*/
void moxie_crypto_sign_open(struct machine *mach);
