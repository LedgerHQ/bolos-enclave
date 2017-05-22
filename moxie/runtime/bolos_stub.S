#include "syscall.h"
	.globl	 bls_set_return
	.type	 bls_set_return,@function
	.globl	 bls_get_input_parameters_length
	.type	 bls_get_input_parameters_length,@function
	.globl	 bls_copy_input_parameters
	.type	 bls_copy_input_parameters,@function
	.globl	 bls_check_api_level
	.type	 bls_check_api_level,@function
	.globl	 _exit
	.type	 _exit,@function
	.globl	 bls_rng_u8
	.type	 bls_rng_u8,@function
	.globl	 bls_rng
	.type	 bls_rng,@function
	.globl	 bls_ripemd160_init
	.type	 bls_ripemd160_init,@function
	.globl	 bls_sha1_init
	.type	 bls_sha1_init,@function
	.globl	 bls_sha256_init
	.type	 bls_sha256_init,@function
	.globl	 bls_sha512_init
	.type	 bls_sha512_init,@function
	.globl	 bls_sha3_init
	.type	 bls_sha3_init,@function
	.globl	 bls_keccak_init
	.type	 bls_keccak_init,@function
	.globl	 bls_hash
	.type	 bls_hash,@function
	.globl	 bls_hmac_ripemd160_init
	.type	 bls_hmac_ripemd160_init,@function
	.globl	 bls_hmac_sha256_init
	.type	 bls_hmac_sha256_init,@function
	.globl	 bls_hmac_sha512_init
	.type	 bls_hmac_sha512_init,@function
	.globl	 bls_hmac
	.type	 bls_hmac,@function
	.globl	 bls_pbkdf2
	.type	 bls_pbkdf2,@function
	.globl	 bls_des_init_key
	.type	 bls_des_init_key,@function
	.globl	 bls_des
	.type	 bls_des,@function
	.globl	 bls_des_iv
	.type	 bls_des_iv,@function
	.globl	 bls_aes_init_key
	.type	 bls_aes_init_key,@function
	.globl	 bls_aes
	.type	 bls_aes,@function
	.globl	 bls_aes_iv
	.type	 bls_aes_iv,@function
	.globl	 bls_aes_iv_gcm
	.type	 bls_aes_iv_gcm,@function
	.globl	 bls_rsa_init_public_key
	.type	 bls_rsa_init_public_key,@function
	.globl	 bls_rsa_init_private_key
	.type	 bls_rsa_init_private_key,@function
	.globl	 bls_rsa_init_private_key_crt
	.type	 bls_rsa_init_private_key_crt,@function
	.globl	 bls_rsa_generate_keypair
	.type	 bls_rsa_generate_keypair,@function
	.globl	 bls_rsa_get_public_key_data
	.type	 bls_rsa_get_public_key_data,@function
	.globl	 bls_rsa_pub
	.type	 bls_rsa_pub,@function
	.globl	 bls_rsa_priv
	.type	 bls_rsa_priv,@function
	.globl	 bls_ecfp_get_domain
	.type	 bls_ecfp_get_domain,@function
	.globl	 bls_ecfp_is_valid_point
	.type	 bls_ecfp_is_valid_point,@function
	.globl	 bls_ecfp_add_point
	.type	 bls_ecfp_add_point,@function
	.globl	 bls_ecdsa_init_public_key
	.type	 bls_ecdsa_init_public_key,@function
	.globl	 bls_ecdsa_init_private_key
	.type	 bls_ecdsa_init_private_key,@function
	.globl	 bls_ecfp_generate_pair
	.type	 bls_ecfp_generate_pair,@function
	.globl	 bls_ecfp_get_public_component
	.type	 bls_ecfp_get_public_component,@function
	.globl	 bls_ecdsa_sign
	.type	 bls_ecdsa_sign,@function
	.globl	 bls_ecdsa_verify
	.type	 bls_ecdsa_verify,@function
	.globl	 bls_schnorr_sign
	.type	 bls_schnorr_sign,@function
	.globl	 bls_schnorr_verify
	.type	 bls_schnorr_verify,@function
	.globl	 bls_ecdh
	.type	 bls_ecdh,@function
	.globl	 bls_crc16
	.type	 bls_crc16,@function
	.globl	 bls_crc16_update
	.type	 bls_crc16_update,@function
	.globl	 bls_math_addm
	.type	 bls_math_addm,@function
	.globl	 bls_math_cmp
	.type	 bls_math_cmp,@function
	.globl	 bls_math_is_zero
	.type	 bls_math_is_zero,@function
	.globl	 bls_math_modm
	.type	 bls_math_modm,@function
	.globl	 bls_wrap
	.type	 bls_wrap,@function
	.globl	 bls_unwrap
	.type	 bls_unwrap,@function
	.globl	 bls_attestation_supported
	.type	 bls_attestation_supported,@function
	.globl	 bls_attestation_device_get_data_signature
	.type	 bls_attestation_device_get_data_signature,@function
	.globl	 bls_endorsement_supported
	.type	 bls_endorsement_supported,@function
	.globl	 bls_endorsement_get_authentication_public_key
	.type	 bls_endorsement_get_authentication_public_key,@function
	.globl	 bls_endorsement_init
	.type	 bls_endorsement_init,@function
	.globl	 bls_endorsement_commit
	.type	 bls_endorsement_commit,@function
	.globl	 bls_endorsement_get_code_hash
	.type	 bls_endorsement_get_code_hash,@function
	.globl	 bls_endorsement_key1_get_app_secret
	.type	 bls_endorsement_key1_get_app_secret,@function
	.globl	 bls_endorsement_key1_sign_data
	.type	 bls_endorsement_key1_sign_data,@function
	.globl	 bls_endorsement_key2_derive_sign_data
	.type	 bls_endorsement_key2_derive_sign_data,@function
	.globl	 bls_endorsement_get_public_key
	.type	 bls_endorsement_get_public_key,@function
	.globl	 bls_endorsement_get_certificate
	.type	 bls_endorsement_get_certificate,@function
	.globl	 bls_antireplay_supported
	.type	 bls_antireplay_supported,@function
	.globl	 bls_antireplay_create
	.type	 bls_antireplay_create,@function
	.globl	 bls_antireplay_query
	.type	 bls_antireplay_query,@function
	.globl	 bls_antireplay_increase
	.type	 bls_antireplay_increase,@function
	.globl	 bls_antireplay_delete
	.type	 bls_antireplay_delete,@function
	.globl	 bls_sharedmemory_get_size
	.type	 bls_sharedmemory_get_size,@function
	.globl	 bls_sharedmemory_read
	.type	 bls_sharedmemory_read,@function
	.globl	 bls_sharedmemory_write
	.type	 bls_sharedmemory_write,@function
	.globl	 bls_time_supported
	.type	 bls_time_supported,@function
	.globl	 bls_time_delta
	.type	 bls_time_delta,@function
	.globl	 bls_time
	.type	 bls_time,@function
	.globl	 bls_continuation_supported
	.type	 bls_continuation_supported,@function
	.globl	 bls_set_continuation
	.type	 bls_set_continuation,@function
	.globl	 bls_debug
	.type	 bls_debug,@function
	.globl	 bls_bip32_derive_secp256k1_private
	.type	 bls_bip32_derive_secp256k1_private,@function
	.globl	 bls_bip32_derive_secp256k1_public
	.type	 bls_bip32_derive_secp256k1_public,@function
	.globl	 bls_wallet_get_state
	.type	 bls_wallet_get_state,@function
	.globl	 bls_wallet_derive
	.type	 bls_wallet_derive,@function
	.globl	 bls_wallet_get_address
	.type	 bls_wallet_get_address,@function
	.globl	 bls_wallet_call
	.type	 bls_wallet_call,@function
	.globl	 bls_wallet_approve_sign
	.type	 bls_wallet_approve_sign,@function
	.globl	 bls_ui_get_capabilities
	.type	 bls_ui_get_capabilities,@function
	.globl	 bls_ui_display_message
	.type	 bls_ui_display_message,@function
	.globl	 bls_ui_display_warning
	.type	 bls_ui_display_warning,@function
	.globl	 bls_ui_display_error
	.type	 bls_ui_display_error,@function
	.globl	 bls_ui_display_choice
	.type	 bls_ui_display_choice,@function
	.globl	 bls_ui_display_qr
	.type	 bls_ui_display_qr,@function
	.globl	 bls_ui_get_user_entry
	.type	 bls_ui_get_user_entry,@function
	.globl	 crypto_secretbox_easy
	.type	 crypto_secretbox_easy,@function
	.globl	 crypto_secretbox_open_easy
	.type	 crypto_secretbox_open_easy,@function
	.globl	 crypto_auth
	.type	 crypto_auth,@function
	.globl	 crypto_auth_verify
	.type	 crypto_auth_verify,@function
	.globl	 crypto_box_keypair
	.type	 crypto_box_keypair,@function
	.globl	 crypto_box_easy
	.type	 crypto_box_easy,@function
	.globl	 crypto_box_open_easy
	.type	 crypto_box_open_easy,@function
	.globl	 crypto_box_seal
	.type	 crypto_box_seal,@function
	.globl	 crypto_box_seal_open
	.type	 crypto_box_seal_open,@function
	.globl	 crypto_sign_keypair
	.type	 crypto_sign_keypair,@function
	.globl	 crypto_sign
	.type	 crypto_sign,@function
	.globl	 crypto_sign_open
	.type	 crypto_sign_open,@function
	.text
/*
* bls_set_return
* $r0 -- addr
* $r1 -- length
* Output:
* void
*/
bls_set_return:
	swi	1
	ret
.Lendbls_set_return:
	.size	bls_set_return,.Lendbls_set_return-bls_set_return

/*
* bls_get_input_parameters_length
* Output:
* size_t
*/
bls_get_input_parameters_length:
	swi	2
	ret
.Lendbls_get_input_parameters_length:
	.size	bls_get_input_parameters_length,.Lendbls_get_input_parameters_length-bls_get_input_parameters_length

/*
* bls_copy_input_parameters
* $r0 -- parameters
* $r1 -- offset
* $r2 -- parametersLength
* Output:
* size_t
*/
bls_copy_input_parameters:
	swi	3
	ret
.Lendbls_copy_input_parameters:
	.size	bls_copy_input_parameters,.Lendbls_copy_input_parameters-bls_copy_input_parameters

/*
* bls_check_api_level
* Output:
* uint32_t
*/
bls_check_api_level:
	swi	4
	ret
.Lendbls_check_api_level:
	.size	bls_check_api_level,.Lendbls_check_api_level-bls_check_api_level

/*
* _exit
* $r0 -- status
* Output:
* void
*/
_exit:
	swi	5
	ret
.Lend_exit:
	.size	_exit,.Lend_exit-_exit

/*
* bls_rng_u8
* Output:
* uint8_t
*/
bls_rng_u8:
	swi	6
	ret
.Lendbls_rng_u8:
	.size	bls_rng_u8,.Lendbls_rng_u8-bls_rng_u8

/*
* bls_rng
* $r0 -- buffer
* $r1 -- len
* Output:
* int
*/
bls_rng:
	swi	7
	ret
.Lendbls_rng:
	.size	bls_rng,.Lendbls_rng-bls_rng

/*
* bls_ripemd160_init
* $r0 -- hash
* Output:
* int
*/
bls_ripemd160_init:
	swi	8
	ret
.Lendbls_ripemd160_init:
	.size	bls_ripemd160_init,.Lendbls_ripemd160_init-bls_ripemd160_init

/*
* bls_sha1_init
* $r0 -- hash
* Output:
* int
*/
bls_sha1_init:
	swi	9
	ret
.Lendbls_sha1_init:
	.size	bls_sha1_init,.Lendbls_sha1_init-bls_sha1_init

/*
* bls_sha256_init
* $r0 -- hash
* Output:
* int
*/
bls_sha256_init:
	swi	10
	ret
.Lendbls_sha256_init:
	.size	bls_sha256_init,.Lendbls_sha256_init-bls_sha256_init

/*
* bls_sha512_init
* $r0 -- hash
* Output:
* int
*/
bls_sha512_init:
	swi	11
	ret
.Lendbls_sha512_init:
	.size	bls_sha512_init,.Lendbls_sha512_init-bls_sha512_init

/*
* bls_sha3_init
* $r0 -- hash
* $r1 -- size
* Output:
* int
*/
bls_sha3_init:
	swi	104
	ret
.Lendbls_sha3_init:
	.size	bls_sha3_init,.Lendbls_sha3_init-bls_sha3_init

/*
* bls_keccak_init
* $r0 -- hash
* $r1 -- size
* Output:
* int
*/
bls_keccak_init:
	swi	105
	ret
.Lendbls_keccak_init:
	.size	bls_keccak_init,.Lendbls_keccak_init-bls_keccak_init

/*
* bls_hash
* $r0 -- hash
* $r1 -- mode
* $r2 -- in
* $r3 -- len
* $r4 -- out
* Output:
* int
*/
bls_hash:
	swi	12
	ret
.Lendbls_hash:
	.size	bls_hash,.Lendbls_hash-bls_hash

/*
* bls_hmac_ripemd160_init
* $r0 -- hmac
* $r1 -- key
* $r2 -- key_len
* Output:
* int
*/
bls_hmac_ripemd160_init:
	swi	13
	ret
.Lendbls_hmac_ripemd160_init:
	.size	bls_hmac_ripemd160_init,.Lendbls_hmac_ripemd160_init-bls_hmac_ripemd160_init

/*
* bls_hmac_sha256_init
* $r0 -- hmac
* $r1 -- key
* $r2 -- key_len
* Output:
* int
*/
bls_hmac_sha256_init:
	swi	14
	ret
.Lendbls_hmac_sha256_init:
	.size	bls_hmac_sha256_init,.Lendbls_hmac_sha256_init-bls_hmac_sha256_init

/*
* bls_hmac_sha512_init
* $r0 -- hmac
* $r1 -- key
* $r2 -- key_len
* Output:
* int
*/
bls_hmac_sha512_init:
	swi	15
	ret
.Lendbls_hmac_sha512_init:
	.size	bls_hmac_sha512_init,.Lendbls_hmac_sha512_init-bls_hmac_sha512_init

/*
* bls_hmac
* $r0 -- hmac
* $r1 -- mode
* $r2 -- in
* $r3 -- len
* $r4 -- mac
* Output:
* int
*/
bls_hmac:
	swi	16
	ret
.Lendbls_hmac:
	.size	bls_hmac,.Lendbls_hmac-bls_hmac

/*
* bls_pbkdf2
* $r0 -- hash
* $r1 -- password
* $r2 -- salt
* $r3 -- iterations
* $r4 -- out
* Output:
* int
*/
bls_pbkdf2:
	swi	17
	ret
.Lendbls_pbkdf2:
	.size	bls_pbkdf2,.Lendbls_pbkdf2-bls_pbkdf2

/*
* bls_des_init_key
* $r0 -- rawkey
* $r1 -- key_len
* $r2 -- key
* Output:
* int
*/
bls_des_init_key:
	swi	18
	ret
.Lendbls_des_init_key:
	.size	bls_des_init_key,.Lendbls_des_init_key-bls_des_init_key

/*
* bls_des
* $r0 -- key
* $r1 -- mode
* $r2 -- in
* $r3 -- out
* Output:
* int
*/
bls_des:
	swi	19
	ret
.Lendbls_des:
	.size	bls_des,.Lendbls_des-bls_des

/*
* bls_des_iv
* $r0 -- key
* $r1 -- mode
* $r2 -- iv
* $r3 -- in
* $r4 -- out
* Output:
* int
*/
bls_des_iv:
	swi	20
	ret
.Lendbls_des_iv:
	.size	bls_des_iv,.Lendbls_des_iv-bls_des_iv

/*
* bls_aes_init_key
* $r0 -- rawkey
* $r1 -- key_len
* $r2 -- key
* Output:
* int
*/
bls_aes_init_key:
	swi	21
	ret
.Lendbls_aes_init_key:
	.size	bls_aes_init_key,.Lendbls_aes_init_key-bls_aes_init_key

/*
* bls_aes
* $r0 -- key
* $r1 -- mode
* $r2 -- in
* $r3 -- out
* Output:
* int
*/
bls_aes:
	swi	22
	ret
.Lendbls_aes:
	.size	bls_aes,.Lendbls_aes-bls_aes

/*
* bls_aes_iv
* $r0 -- key
* $r1 -- mode
* $r2 -- iv
* $r3 -- in
* $r4 -- out
* Output:
* int
*/
bls_aes_iv:
	swi	23
	ret
.Lendbls_aes_iv:
	.size	bls_aes_iv,.Lendbls_aes_iv-bls_aes_iv

/*
* bls_aes_iv_gcm
* $r0 -- key
* $r1 -- mode
* $r2 -- in
* $r3 -- iv
* $r4 -- aadTag
* $r5 -- out
* Output:
* int
*/
bls_aes_iv_gcm:
	swi	24
	ret
.Lendbls_aes_iv_gcm:
	.size	bls_aes_iv_gcm,.Lendbls_aes_iv_gcm-bls_aes_iv_gcm

/*
* bls_rsa_init_public_key
* $r0 -- keyData
* $r1 -- key
* Output:
* int
*/
bls_rsa_init_public_key:
	swi	25
	ret
.Lendbls_rsa_init_public_key:
	.size	bls_rsa_init_public_key,.Lendbls_rsa_init_public_key-bls_rsa_init_public_key

/*
* bls_rsa_init_private_key
* $r0 -- keyData
* $r1 -- key
* Output:
* int
*/
bls_rsa_init_private_key:
	swi	26
	ret
.Lendbls_rsa_init_private_key:
	.size	bls_rsa_init_private_key,.Lendbls_rsa_init_private_key-bls_rsa_init_private_key

/*
* bls_rsa_init_private_key_crt
* $r0 -- crtParameters
* $r1 -- key
* Output:
* int
*/
bls_rsa_init_private_key_crt:
	swi	27
	ret
.Lendbls_rsa_init_private_key_crt:
	.size	bls_rsa_init_private_key_crt,.Lendbls_rsa_init_private_key_crt-bls_rsa_init_private_key_crt

/*
* bls_rsa_generate_keypair
* $r0 -- modulus_len
* $r1 -- privateKey
* $r2 -- publicKey
* $r3 -- generatedKeypairInfo
* Output:
* int
*/
bls_rsa_generate_keypair:
	swi	28
	ret
.Lendbls_rsa_generate_keypair:
	.size	bls_rsa_generate_keypair,.Lendbls_rsa_generate_keypair-bls_rsa_generate_keypair

/*
* bls_rsa_get_public_key_data
* $r0 -- publicKey
* $r1 -- keyInfo
* Output:
* int
*/
bls_rsa_get_public_key_data:
	swi	29
	ret
.Lendbls_rsa_get_public_key_data:
	.size	bls_rsa_get_public_key_data,.Lendbls_rsa_get_public_key_data-bls_rsa_get_public_key_data

/*
* bls_rsa_pub
* $r0 -- key
* $r1 -- mode
* $r2 -- hashID
* $r3 -- src
* $r4 -- dest
* Output:
* int
*/
bls_rsa_pub:
	swi	30
	ret
.Lendbls_rsa_pub:
	.size	bls_rsa_pub,.Lendbls_rsa_pub-bls_rsa_pub

/*
* bls_rsa_priv
* $r0 -- key
* $r1 -- mode
* $r2 -- hashID
* $r3 -- src
* $r4 -- dest
* Output:
* int
*/
bls_rsa_priv:
	swi	31
	ret
.Lendbls_rsa_priv:
	.size	bls_rsa_priv,.Lendbls_rsa_priv-bls_rsa_priv

/*
* bls_ecfp_get_domain
* $r0 -- curve
* Output:
* bls_curve_domain_t*
*/
bls_ecfp_get_domain:
	swi	32
	ret
.Lendbls_ecfp_get_domain:
	.size	bls_ecfp_get_domain,.Lendbls_ecfp_get_domain-bls_ecfp_get_domain

/*
* bls_ecfp_is_valid_point
* $r0 -- domain
* $r1 -- point
* Output:
* int
*/
bls_ecfp_is_valid_point:
	swi	33
	ret
.Lendbls_ecfp_is_valid_point:
	.size	bls_ecfp_is_valid_point,.Lendbls_ecfp_is_valid_point-bls_ecfp_is_valid_point

/*
* bls_ecfp_add_point
* $r0 -- domain
* $r1 -- R
* $r2 -- P
* $r3 -- Q
* Output:
* int
*/
bls_ecfp_add_point:
	swi	34
	ret
.Lendbls_ecfp_add_point:
	.size	bls_ecfp_add_point,.Lendbls_ecfp_add_point-bls_ecfp_add_point

/*
* bls_ecdsa_init_public_key
* $r0 -- curve
* $r1 -- rawkey
* $r2 -- key_len
* $r3 -- key
* Output:
* int
*/
bls_ecdsa_init_public_key:
	swi	35
	ret
.Lendbls_ecdsa_init_public_key:
	.size	bls_ecdsa_init_public_key,.Lendbls_ecdsa_init_public_key-bls_ecdsa_init_public_key

/*
* bls_ecdsa_init_private_key
* $r0 -- curve
* $r1 -- rawkey
* $r2 -- key_len
* $r3 -- key
* Output:
* int
*/
bls_ecdsa_init_private_key:
	swi	36
	ret
.Lendbls_ecdsa_init_private_key:
	.size	bls_ecdsa_init_private_key,.Lendbls_ecdsa_init_private_key-bls_ecdsa_init_private_key

/*
* bls_ecfp_generate_pair
* $r0 -- curve
* $r1 -- public_key
* $r2 -- private_key
* $r3 -- d
* Output:
* int
*/
bls_ecfp_generate_pair:
	swi	37
	ret
.Lendbls_ecfp_generate_pair:
	.size	bls_ecfp_generate_pair,.Lendbls_ecfp_generate_pair-bls_ecfp_generate_pair

/*
* bls_ecfp_get_public_component
* $r0 -- public_key
* $r1 -- W
* Output:
* int
*/
bls_ecfp_get_public_component:
	swi	38
	ret
.Lendbls_ecfp_get_public_component:
	.size	bls_ecfp_get_public_component,.Lendbls_ecfp_get_public_component-bls_ecfp_get_public_component

/*
* bls_ecdsa_sign
* $r0 -- key
* $r1 -- mode
* $r2 -- hashID
* $r3 -- hash
* $r4 -- hash_len
* $r5 -- sig
* Output:
* int
*/
bls_ecdsa_sign:
	swi	39
	ret
.Lendbls_ecdsa_sign:
	.size	bls_ecdsa_sign,.Lendbls_ecdsa_sign-bls_ecdsa_sign

/*
* bls_ecdsa_verify
* $r0 -- key
* $r1 -- mode
* $r2 -- hashID
* $r3 -- hash
* $r4 -- hash_len
* $r5 -- sig
* Output:
* int
*/
bls_ecdsa_verify:
	swi	40
	ret
.Lendbls_ecdsa_verify:
	.size	bls_ecdsa_verify,.Lendbls_ecdsa_verify-bls_ecdsa_verify

/*
* bls_schnorr_sign
* $r0 -- key
* $r1 -- mode
* $r2 -- hashID
* $r3 -- hash
* $r4 -- hash_len
* $r5 -- sig
* Output:
* int
*/
bls_schnorr_sign:
	swi	41
	ret
.Lendbls_schnorr_sign:
	.size	bls_schnorr_sign,.Lendbls_schnorr_sign-bls_schnorr_sign

/*
* bls_schnorr_verify
* $r0 -- key
* $r1 -- mode
* $r2 -- hashID
* $r3 -- hash
* $r4 -- hash_len
* $r5 -- sig
* Output:
* int
*/
bls_schnorr_verify:
	swi	42
	ret
.Lendbls_schnorr_verify:
	.size	bls_schnorr_verify,.Lendbls_schnorr_verify-bls_schnorr_verify

/*
* bls_ecdh
* $r0 -- key
* $r1 -- mode
* $r2 -- public_point
* $r3 -- secret
* Output:
* int
*/
bls_ecdh:
	swi	43
	ret
.Lendbls_ecdh:
	.size	bls_ecdh,.Lendbls_ecdh-bls_ecdh

/*
* bls_crc16
* $r0 -- buffer
* $r1 -- len
* Output:
* uint16_t
*/
bls_crc16:
	swi	44
	ret
.Lendbls_crc16:
	.size	bls_crc16,.Lendbls_crc16-bls_crc16

/*
* bls_crc16_update
* $r0 -- crc
* $r1 -- buffer
* $r2 -- len
* Output:
* uint16_t
*/
bls_crc16_update:
	swi	45
	ret
.Lendbls_crc16_update:
	.size	bls_crc16_update,.Lendbls_crc16_update-bls_crc16_update

/*
* bls_math_addm
* $r0 -- r
* $r1 -- a
* $r2 -- b
* $r3 -- m
* $r4 -- len
* Output:
* void
*/
bls_math_addm:
	swi	46
	ret
.Lendbls_math_addm:
	.size	bls_math_addm,.Lendbls_math_addm-bls_math_addm

/*
* bls_math_cmp
* $r0 -- a
* $r1 -- b
* $r2 -- len
* Output:
* int
*/
bls_math_cmp:
	swi	47
	ret
.Lendbls_math_cmp:
	.size	bls_math_cmp,.Lendbls_math_cmp-bls_math_cmp

/*
* bls_math_is_zero
* $r0 -- a
* $r1 -- len
* Output:
* int
*/
bls_math_is_zero:
	swi	48
	ret
.Lendbls_math_is_zero:
	.size	bls_math_is_zero,.Lendbls_math_is_zero-bls_math_is_zero

/*
* bls_math_modm
* $r0 -- v
* $r1 -- len_v
* $r2 -- m
* $r3 -- len_m
* Output:
* void
*/
bls_math_modm:
	swi	49
	ret
.Lendbls_math_modm:
	.size	bls_math_modm,.Lendbls_math_modm-bls_math_modm

/*
* bls_wrap
* $r0 -- scope
* $r1 -- in
* $r2 -- length
* $r3 -- out
* $r4 -- outLength
* Output:
* unsigned int
*/
bls_wrap:
	swi	50
	ret
.Lendbls_wrap:
	.size	bls_wrap,.Lendbls_wrap-bls_wrap

/*
* bls_unwrap
* $r0 -- scope
* $r1 -- in
* $r2 -- length
* $r3 -- out
* $r4 -- outLength
* Output:
* unsigned int
*/
bls_unwrap:
	swi	51
	ret
.Lendbls_unwrap:
	.size	bls_unwrap,.Lendbls_unwrap-bls_unwrap

/*
* bls_attestation_supported
* Output:
* int
*/
bls_attestation_supported:
	swi	52
	ret
.Lendbls_attestation_supported:
	.size	bls_attestation_supported,.Lendbls_attestation_supported-bls_attestation_supported

/*
* bls_attestation_device_get_data_signature
* $r0 -- in
* $r1 -- length
* $r2 -- out
* $r3 -- outLength
* Output:
* int
*/
bls_attestation_device_get_data_signature:
	swi	53
	ret
.Lendbls_attestation_device_get_data_signature:
	.size	bls_attestation_device_get_data_signature,.Lendbls_attestation_device_get_data_signature-bls_attestation_device_get_data_signature

/*
* bls_endorsement_supported
* $r0 -- key
* Output:
* int
*/
bls_endorsement_supported:
	swi	54
	ret
.Lendbls_endorsement_supported:
	.size	bls_endorsement_supported,.Lendbls_endorsement_supported-bls_endorsement_supported

/*
* bls_endorsement_get_authentication_public_key
* $r0 -- out
* $r1 -- outLength
* Output:
* int
*/
bls_endorsement_get_authentication_public_key:
	swi	55
	ret
.Lendbls_endorsement_get_authentication_public_key:
	.size	bls_endorsement_get_authentication_public_key,.Lendbls_endorsement_get_authentication_public_key-bls_endorsement_get_authentication_public_key

/*
* bls_endorsement_init
* $r0 -- key
* $r1 -- out
* $r2 -- outLength
* Output:
* int
*/
bls_endorsement_init:
	swi	56
	ret
.Lendbls_endorsement_init:
	.size	bls_endorsement_init,.Lendbls_endorsement_init-bls_endorsement_init

/*
* bls_endorsement_commit
* $r0 -- key
* $r1 -- response
* $r2 -- responseLength
* Output:
* int
*/
bls_endorsement_commit:
	swi	57
	ret
.Lendbls_endorsement_commit:
	.size	bls_endorsement_commit,.Lendbls_endorsement_commit-bls_endorsement_commit

/*
* bls_endorsement_get_code_hash
* $r0 -- out
* $r1 -- outLength
* Output:
* int
*/
bls_endorsement_get_code_hash:
	swi	58
	ret
.Lendbls_endorsement_get_code_hash:
	.size	bls_endorsement_get_code_hash,.Lendbls_endorsement_get_code_hash-bls_endorsement_get_code_hash

/*
* bls_endorsement_key1_get_app_secret
* $r0 -- out
* $r1 -- outLength
* Output:
* int
*/
bls_endorsement_key1_get_app_secret:
	swi	59
	ret
.Lendbls_endorsement_key1_get_app_secret:
	.size	bls_endorsement_key1_get_app_secret,.Lendbls_endorsement_key1_get_app_secret-bls_endorsement_key1_get_app_secret

/*
* bls_endorsement_key1_sign_data
* $r0 -- in
* $r1 -- length
* $r2 -- out
* $r3 -- outLength
* Output:
* int
*/
bls_endorsement_key1_sign_data:
	swi	60
	ret
.Lendbls_endorsement_key1_sign_data:
	.size	bls_endorsement_key1_sign_data,.Lendbls_endorsement_key1_sign_data-bls_endorsement_key1_sign_data

/*
* bls_endorsement_key2_derive_sign_data
* $r0 -- in
* $r1 -- length
* $r2 -- out
* $r3 -- outLength
* Output:
* int
*/
bls_endorsement_key2_derive_sign_data:
	swi	61
	ret
.Lendbls_endorsement_key2_derive_sign_data:
	.size	bls_endorsement_key2_derive_sign_data,.Lendbls_endorsement_key2_derive_sign_data-bls_endorsement_key2_derive_sign_data

/*
* bls_endorsement_get_public_key
* $r0 -- endorsementKey
* $r1 -- out
* $r2 -- outLength
* Output:
* int
*/
bls_endorsement_get_public_key:
	swi	62
	ret
.Lendbls_endorsement_get_public_key:
	.size	bls_endorsement_get_public_key,.Lendbls_endorsement_get_public_key-bls_endorsement_get_public_key

/*
* bls_endorsement_get_certificate
* $r0 -- endorsementKey
* $r1 -- out
* $r2 -- outLength
* Output:
* int
*/
bls_endorsement_get_certificate:
	swi	63
	ret
.Lendbls_endorsement_get_certificate:
	.size	bls_endorsement_get_certificate,.Lendbls_endorsement_get_certificate-bls_endorsement_get_certificate

/*
* bls_antireplay_supported
* Output:
* int
*/
bls_antireplay_supported:
	swi	89
	ret
.Lendbls_antireplay_supported:
	.size	bls_antireplay_supported,.Lendbls_antireplay_supported-bls_antireplay_supported

/*
* bls_antireplay_create
* $r0 -- referenceOut
* $r1 -- referenceOutLength
* Output:
* int
*/
bls_antireplay_create:
	swi	90
	ret
.Lendbls_antireplay_create:
	.size	bls_antireplay_create,.Lendbls_antireplay_create-bls_antireplay_create

/*
* bls_antireplay_query
* $r0 -- reference
* $r1 -- referenceLength
* $r2 -- value
* Output:
* int
*/
bls_antireplay_query:
	swi	91
	ret
.Lendbls_antireplay_query:
	.size	bls_antireplay_query,.Lendbls_antireplay_query-bls_antireplay_query

/*
* bls_antireplay_increase
* $r0 -- reference
* $r1 -- referenceLength
* Output:
* int
*/
bls_antireplay_increase:
	swi	92
	ret
.Lendbls_antireplay_increase:
	.size	bls_antireplay_increase,.Lendbls_antireplay_increase-bls_antireplay_increase

/*
* bls_antireplay_delete
* $r0 -- reference
* $r1 -- referenceLength
* Output:
* int
*/
bls_antireplay_delete:
	swi	93
	ret
.Lendbls_antireplay_delete:
	.size	bls_antireplay_delete,.Lendbls_antireplay_delete-bls_antireplay_delete

/*
* bls_sharedmemory_get_size
* Output:
* int
*/
bls_sharedmemory_get_size:
	swi	96
	ret
.Lendbls_sharedmemory_get_size:
	.size	bls_sharedmemory_get_size,.Lendbls_sharedmemory_get_size-bls_sharedmemory_get_size

/*
* bls_sharedmemory_read
* $r0 -- parameters
* $r1 -- offset
* $r2 -- parametersLength
* Output:
* size_t
*/
bls_sharedmemory_read:
	swi	97
	ret
.Lendbls_sharedmemory_read:
	.size	bls_sharedmemory_read,.Lendbls_sharedmemory_read-bls_sharedmemory_read

/*
* bls_sharedmemory_write
* $r0 -- parameters
* $r1 -- offset
* $r2 -- parametersLength
* Output:
* size_t
*/
bls_sharedmemory_write:
	swi	98
	ret
.Lendbls_sharedmemory_write:
	.size	bls_sharedmemory_write,.Lendbls_sharedmemory_write-bls_sharedmemory_write

/*
* bls_time_supported
* Output:
* int
*/
bls_time_supported:
	swi	94
	ret
.Lendbls_time_supported:
	.size	bls_time_supported,.Lendbls_time_supported-bls_time_supported

/*
* bls_time_delta
* $r0 -- referenceOut
* $r1 -- referenceOutLength
* $r2 -- delta
* $r3 -- trusted
* Output:
* int
*/
bls_time_delta:
	swi	95
	ret
.Lendbls_time_delta:
	.size	bls_time_delta,.Lendbls_time_delta-bls_time_delta

/*
* bls_time
* $r0 -- time
* $r1 -- trusted
* Output:
* int
*/
bls_time:
	swi	99
	ret
.Lendbls_time:
	.size	bls_time,.Lendbls_time-bls_time

/*
* bls_continuation_supported
* Output:
* int
*/
bls_continuation_supported:
	swi	100
	ret
.Lendbls_continuation_supported:
	.size	bls_continuation_supported,.Lendbls_continuation_supported-bls_continuation_supported

/*
* bls_set_continuation
* $r0 -- addr
* $r1 -- length
* Output:
* void
*/
bls_set_continuation:
	swi	101
	ret
.Lendbls_set_continuation:
	.size	bls_set_continuation,.Lendbls_set_continuation-bls_set_continuation

/*
* bls_debug
* $r0 -- text
* Output:
* void
*/
bls_debug:
	swi	64
	ret
.Lendbls_debug:
	.size	bls_debug,.Lendbls_debug-bls_debug

/*
* bls_bip32_derive_secp256k1_private
* $r0 -- privateKey
* $r1 -- chainCode
* $r2 -- index
* Output:
* int
*/
bls_bip32_derive_secp256k1_private:
	swi	102
	ret
.Lendbls_bip32_derive_secp256k1_private:
	.size	bls_bip32_derive_secp256k1_private,.Lendbls_bip32_derive_secp256k1_private-bls_bip32_derive_secp256k1_private

/*
* bls_bip32_derive_secp256k1_public
* $r0 -- publicKey
* $r1 -- chainCode
* $r2 -- index
* Output:
* int
*/
bls_bip32_derive_secp256k1_public:
	swi	103
	ret
.Lendbls_bip32_derive_secp256k1_public:
	.size	bls_bip32_derive_secp256k1_public,.Lendbls_bip32_derive_secp256k1_public-bls_bip32_derive_secp256k1_public

/*
* bls_wallet_get_state
* Output:
* int
*/
bls_wallet_get_state:
	swi	65
	ret
.Lendbls_wallet_get_state:
	.size	bls_wallet_get_state,.Lendbls_wallet_get_state-bls_wallet_get_state

/*
* bls_wallet_derive
* $r0 -- details
* $r1 -- path
* $r2 -- pathLength
* $r3 -- chainCode
* $r4 -- privateKey
* $r5 -- publicKey
* Output:
* int
*/
bls_wallet_derive:
	swi	66
	ret
.Lendbls_wallet_derive:
	.size	bls_wallet_derive,.Lendbls_wallet_derive-bls_wallet_derive

/*
* bls_wallet_get_address
* $r0 -- publicKey
* $r1 -- address
* $r2 -- addressLength
* $r3 -- compressed
* Output:
* int
*/
bls_wallet_get_address:
	swi	67
	ret
.Lendbls_wallet_get_address:
	.size	bls_wallet_get_address,.Lendbls_wallet_get_address-bls_wallet_get_address

/*
* bls_wallet_call
* $r0 -- apdu
* Output:
* int
*/
bls_wallet_call:
	swi	68
	ret
.Lendbls_wallet_call:
	.size	bls_wallet_call,.Lendbls_wallet_call-bls_wallet_call

/*
* bls_wallet_approve_sign
* $r0 -- status
* Output:
* int
*/
bls_wallet_approve_sign:
	swi	69
	ret
.Lendbls_wallet_approve_sign:
	.size	bls_wallet_approve_sign,.Lendbls_wallet_approve_sign-bls_wallet_approve_sign

/*
* bls_ui_get_capabilities
* Output:
* int
*/
bls_ui_get_capabilities:
	swi	70
	ret
.Lendbls_ui_get_capabilities:
	.size	bls_ui_get_capabilities,.Lendbls_ui_get_capabilities-bls_ui_get_capabilities

/*
* bls_ui_display_message
* $r0 -- text
* Output:
* int
*/
bls_ui_display_message:
	swi	71
	ret
.Lendbls_ui_display_message:
	.size	bls_ui_display_message,.Lendbls_ui_display_message-bls_ui_display_message

/*
* bls_ui_display_warning
* $r0 -- text
* Output:
* int
*/
bls_ui_display_warning:
	swi	72
	ret
.Lendbls_ui_display_warning:
	.size	bls_ui_display_warning,.Lendbls_ui_display_warning-bls_ui_display_warning

/*
* bls_ui_display_error
* $r0 -- text
* Output:
* int
*/
bls_ui_display_error:
	swi	73
	ret
.Lendbls_ui_display_error:
	.size	bls_ui_display_error,.Lendbls_ui_display_error-bls_ui_display_error

/*
* bls_ui_display_choice
* $r0 -- message
* Output:
* int
*/
bls_ui_display_choice:
	swi	74
	ret
.Lendbls_ui_display_choice:
	.size	bls_ui_display_choice,.Lendbls_ui_display_choice-bls_ui_display_choice

/*
* bls_ui_display_qr
* $r0 -- message
* $r1 -- data
* $r2 -- dataSize
* Output:
* int
*/
bls_ui_display_qr:
	swi	75
	ret
.Lendbls_ui_display_qr:
	.size	bls_ui_display_qr,.Lendbls_ui_display_qr-bls_ui_display_qr

/*
* bls_ui_get_user_entry
* $r0 -- message
* $r1 -- out
* $r2 -- outLength
* Output:
* int
*/
bls_ui_get_user_entry:
	swi	76
	ret
.Lendbls_ui_get_user_entry:
	.size	bls_ui_get_user_entry,.Lendbls_ui_get_user_entry-bls_ui_get_user_entry

/*
* crypto_secretbox_easy
* $r0 -- c
* $r1 -- m
* $r2 -- mlen
* $r3 -- n
* $r4 -- k
* Output:
* int
*/
crypto_secretbox_easy:
	swi	77
	ret
.Lendcrypto_secretbox_easy:
	.size	crypto_secretbox_easy,.Lendcrypto_secretbox_easy-crypto_secretbox_easy

/*
* crypto_secretbox_open_easy
* $r0 -- m
* $r1 -- c
* $r2 -- clen
* $r3 -- n
* $r4 -- k
* Output:
* int
*/
crypto_secretbox_open_easy:
	swi	78
	ret
.Lendcrypto_secretbox_open_easy:
	.size	crypto_secretbox_open_easy,.Lendcrypto_secretbox_open_easy-crypto_secretbox_open_easy

/*
* crypto_auth
* $r0 -- out
* $r1 -- in
* $r2 -- inlen
* $r3 -- k
* Output:
* int
*/
crypto_auth:
	swi	79
	ret
.Lendcrypto_auth:
	.size	crypto_auth,.Lendcrypto_auth-crypto_auth

/*
* crypto_auth_verify
* $r0 -- h
* $r1 -- in
* $r2 -- inlen
* $r3 -- k
* Output:
* int
*/
crypto_auth_verify:
	swi	80
	ret
.Lendcrypto_auth_verify:
	.size	crypto_auth_verify,.Lendcrypto_auth_verify-crypto_auth_verify

/*
* crypto_box_keypair
* $r0 -- pk
* $r1 -- sk
* Output:
* int
*/
crypto_box_keypair:
	swi	81
	ret
.Lendcrypto_box_keypair:
	.size	crypto_box_keypair,.Lendcrypto_box_keypair-crypto_box_keypair

/*
* crypto_box_easy
* $r0 -- c
* $r1 -- m
* $r2 -- mlen
* $r3 -- n
* $r4 -- pk
* $r5 -- sk
* Output:
* int
*/
crypto_box_easy:
	swi	82
	ret
.Lendcrypto_box_easy:
	.size	crypto_box_easy,.Lendcrypto_box_easy-crypto_box_easy

/*
* crypto_box_open_easy
* $r0 -- m
* $r1 -- c
* $r2 -- clen
* $r3 -- n
* $r4 -- pk
* $r5 -- sk
* Output:
* int
*/
crypto_box_open_easy:
	swi	83
	ret
.Lendcrypto_box_open_easy:
	.size	crypto_box_open_easy,.Lendcrypto_box_open_easy-crypto_box_open_easy

/*
* crypto_box_seal
* $r0 -- c
* $r1 -- m
* $r2 -- mlen
* $r3 -- pk
* Output:
* int
*/
crypto_box_seal:
	swi	84
	ret
.Lendcrypto_box_seal:
	.size	crypto_box_seal,.Lendcrypto_box_seal-crypto_box_seal

/*
* crypto_box_seal_open
* $r0 -- m
* $r1 -- c
* $r2 -- clen
* $r3 -- pk
* $r4 -- sk
* Output:
* int
*/
crypto_box_seal_open:
	swi	85
	ret
.Lendcrypto_box_seal_open:
	.size	crypto_box_seal_open,.Lendcrypto_box_seal_open-crypto_box_seal_open

/*
* crypto_sign_keypair
* $r0 -- pk
* $r1 -- sk
* Output:
* int
*/
crypto_sign_keypair:
	swi	86
	ret
.Lendcrypto_sign_keypair:
	.size	crypto_sign_keypair,.Lendcrypto_sign_keypair-crypto_sign_keypair

/*
* crypto_sign
* $r0 -- sm
* $r1 -- smlen_p
* $r2 -- m
* $r3 -- mlen
* $r4 -- sk
* Output:
* int
*/
crypto_sign:
	swi	87
	ret
.Lendcrypto_sign:
	.size	crypto_sign,.Lendcrypto_sign-crypto_sign

/*
* crypto_sign_open
* $r0 -- m
* $r1 -- mlen_p
* $r2 -- sm
* $r3 -- smlen
* $r4 -- pk
* Output:
* int
*/
crypto_sign_open:
	swi	88
	ret
.Lendcrypto_sign_open:
	.size	crypto_sign_open,.Lendcrypto_sign_open-crypto_sign_open

