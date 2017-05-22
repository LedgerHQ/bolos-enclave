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
#include "bolos.h"
#include "machine.h"
#include "moxie_swi_bolos.h"

int moxie_swi_dispatcher(struct machine *mach, int swi) {
    switch (swi) {
    case 1:
        moxie_bls_set_return(mach);
        break;
    case 2:
        moxie_bls_get_input_parameters_length(mach);
        break;
    case 3:
        moxie_bls_copy_input_parameters(mach);
        break;
    case 4:
        moxie_bls_check_api_level(mach);
        break;
    case 5:
        moxie__exit(mach);
        break;
    case 6:
        moxie_bls_rng_u8(mach);
        break;
    case 7:
        moxie_bls_rng(mach);
        break;
    case 8:
        moxie_bls_ripemd160_init(mach);
        break;
    case 9:
        moxie_bls_sha1_init(mach);
        break;
    case 10:
        moxie_bls_sha256_init(mach);
        break;
    case 11:
        moxie_bls_sha512_init(mach);
        break;
    case 104:
        moxie_bls_sha3_init(mach);
        break;
    case 105:
        moxie_bls_keccak_init(mach);
        break;
    case 12:
        moxie_bls_hash(mach);
        break;
    case 13:
        moxie_bls_hmac_ripemd160_init(mach);
        break;
    case 14:
        moxie_bls_hmac_sha256_init(mach);
        break;
    case 15:
        moxie_bls_hmac_sha512_init(mach);
        break;
    case 16:
        moxie_bls_hmac(mach);
        break;
    case 17:
        moxie_bls_pbkdf2(mach);
        break;
    case 18:
        moxie_bls_des_init_key(mach);
        break;
    case 19:
        moxie_bls_des(mach);
        break;
    case 20:
        moxie_bls_des_iv(mach);
        break;
    case 21:
        moxie_bls_aes_init_key(mach);
        break;
    case 22:
        moxie_bls_aes(mach);
        break;
    case 23:
        moxie_bls_aes_iv(mach);
        break;
    case 24:
        moxie_bls_aes_iv_gcm(mach);
        break;
    case 25:
        moxie_bls_rsa_init_public_key(mach);
        break;
    case 26:
        moxie_bls_rsa_init_private_key(mach);
        break;
    case 27:
        moxie_bls_rsa_init_private_key_crt(mach);
        break;
    case 28:
        moxie_bls_rsa_generate_keypair(mach);
        break;
    case 29:
        moxie_bls_rsa_get_public_key_data(mach);
        break;
    case 30:
        moxie_bls_rsa_pub(mach);
        break;
    case 31:
        moxie_bls_rsa_priv(mach);
        break;
    case 32:
        moxie_bls_ecfp_get_domain(mach);
        break;
    case 33:
        moxie_bls_ecfp_is_valid_point(mach);
        break;
    case 34:
        moxie_bls_ecfp_add_point(mach);
        break;
    case 35:
        moxie_bls_ecdsa_init_public_key(mach);
        break;
    case 36:
        moxie_bls_ecdsa_init_private_key(mach);
        break;
    case 37:
        moxie_bls_ecfp_generate_pair(mach);
        break;
    case 38:
        moxie_bls_ecfp_get_public_component(mach);
        break;
    case 39:
        moxie_bls_ecdsa_sign(mach);
        break;
    case 40:
        moxie_bls_ecdsa_verify(mach);
        break;
    case 41:
        moxie_bls_schnorr_sign(mach);
        break;
    case 42:
        moxie_bls_schnorr_verify(mach);
        break;
    case 43:
        moxie_bls_ecdh(mach);
        break;
    case 50:
        moxie_bls_wrap(mach);
        break;
    case 51:
        moxie_bls_unwrap(mach);
        break;
    case 54:
        moxie_bls_endorsement_supported(mach);
        break;
    case 55:
        moxie_bls_endorsement_get_authentication_public_key(mach);
        break;
    case 56:
        moxie_bls_endorsement_init(mach);
        break;
    case 57:
        moxie_bls_endorsement_commit(mach);
        break;
    case 58:
        moxie_bls_endorsement_get_code_hash(mach);
        break;
    case 59:
        moxie_bls_endorsement_key1_get_app_secret(mach);
        break;
    case 60:
        moxie_bls_endorsement_key1_sign_data(mach);
        break;
    case 61:
        moxie_bls_endorsement_key2_derive_sign_data(mach);
        break;
    case 62:
        moxie_bls_endorsement_get_public_key(mach);
        break;
    case 63:
        moxie_bls_endorsement_get_certificate(mach);
        break;
    case 64:
        moxie_bls_debug(mach);
        break;
    case 77:
        moxie_crypto_secretbox_easy(mach);
        break;
    case 78:
        moxie_crypto_secretbox_open_easy(mach);
        break;
    case 79:
        moxie_crypto_auth(mach);
        break;
    case 80:
        moxie_crypto_auth_verify(mach);
        break;
    case 81:
        moxie_crypto_box_keypair(mach);
        break;
    case 82:
        moxie_crypto_box_easy(mach);
        break;
    case 83:
        moxie_crypto_box_open_easy(mach);
        break;
    case 84:
        moxie_crypto_box_seal(mach);
        break;
    case 85:
        moxie_crypto_box_seal_open(mach);
        break;
    case 86:
        moxie_crypto_sign_keypair(mach);
        break;
    case 87:
        moxie_crypto_sign(mach);
        break;
    case 88:
        moxie_crypto_sign_open(mach);
        break;
    case 89:
        moxie_bls_antireplay_supported(mach);
        break;
    case 90:
        moxie_bls_antireplay_create(mach);
        break;
    case 91:
        moxie_bls_antireplay_query(mach);
        break;
    case 92:
        moxie_bls_antireplay_increase(mach);
        break;
    case 93:
        moxie_bls_antireplay_delete(mach);
        break;
    case 94:
        moxie_bls_time_supported(mach);
        break;
    case 95:
        moxie_bls_time_delta(mach);
        break;
    case 96:
        moxie_bls_sharedmemory_get_size(mach);
        break;
    case 97:
        moxie_bls_sharedmemory_read(mach);
        break;
    case 98:
        moxie_bls_sharedmemory_write(mach);
        break;
    case 99:
        moxie_bls_time(mach);
        break;
    case 100:
        moxie_bls_continuation_supported(mach);
        break;
    case 101:
        moxie_bls_set_continuation(mach);
        break;
    case 102:
        moxie_bls_bip32_derive_secp256k1_private(mach);
        break;
    case 103:
        moxie_bls_bip32_derive_secp256k1_public(mach);
        break;

    default:
        return 0;
    }
    return 1;
}
