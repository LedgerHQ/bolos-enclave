/*
*******************************************************************************    
*   BOLOS TEE Samples
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


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "bolos.h"

const unsigned char PASSWORD[] = "blur hard tenant found tenant reopen warrior cable animal egg suit amateur session ranch talent bread shock giggle flip gift hood catch panther dutch";
const unsigned char SALT[] = "mnemonic    ";
const unsigned char SEED[] = "Bitcoin seed";

const unsigned char PUBLIC_KEY[] = { 0x02,0x68,0xef,0x08,0x7e,0x9a,0x0f,0xd6,0x77,0x42,0x47,0x33,0x0d,0x2c,0xc7,0x82,0x78,0x53,0xd5,0x68,0xa3,0x7c,0xa1,0x76,0x41,0xe1,0x7e,0x45,0xef,0x79,0x41,0x07, 0x24 };

int main(int argc, char **argv) {
	uint32_t i;
	bls_area_t password;
	bls_area_t salt;
        bls_ecfp_public_key_t publicKey = {0};
        bls_ecfp_private_key_t privateKey = {0};
	unsigned char dest[64];
	unsigned char dest2[64];
	unsigned char result[65];
	uint8_t ok = 1;
	bls_hmac_sha512_t sha512;
	password.buffer = PASSWORD;
	password.length = sizeof(PASSWORD) - 1;
	salt.buffer = SALT;
	salt.length = sizeof(SALT) - 1;
	bls_pbkdf2(BLS_SHA512, &password, &salt, 2048, dest);
        bls_hmac_sha512_init(&sha512, SEED, sizeof(SEED) - 1);
        bls_hmac((bls_hmac_t*)&sha512, BLS_LAST, dest, 64, dest);
	bls_bip32_derive_secp256k1_private(dest, dest+32, 0x8000002c);
	bls_bip32_derive_secp256k1_private(dest, dest+32, 0x80000000);
	bls_bip32_derive_secp256k1_private(dest, dest+32, 0x80000000);
	for (i=0; i<64; i++) {
		dest2[i] = dest[i];
	}
	bls_bip32_derive_secp256k1_private(dest, dest+32, 0x00000000);
	bls_bip32_derive_secp256k1_private(dest, dest+32, 0x00000000);
        bls_ecdsa_init_private_key(BLS_CURVE_256K1, dest, 32, &privateKey);
        bls_ecdsa_init_public_key(BLS_CURVE_256K1, NULL, 0, &publicKey);
        bls_ecfp_generate_pair(BLS_CURVE_256K1, &publicKey, &privateKey, NULL);
        bls_ecfp_get_public_component(&publicKey, result);
	result[0] = ((result[64] & 1) ? 0x03 : 0x02);
        for (i=0; i<sizeof(PUBLIC_KEY); i++) {
                if (result[i] != PUBLIC_KEY[i]) {
                        ok = 0;
                        break;
                }
        }
	if (ok) {
		bls_debug("BTC derive private ok\n");
	}
	else {
		bls_debug("Fail BTC derive private\n");
	}
	// Test public derivation
	ok = 1;
	bls_ecdsa_init_private_key(BLS_CURVE_256K1, dest2, 32, &privateKey);
        bls_ecdsa_init_public_key(BLS_CURVE_256K1, NULL, 0, &publicKey);
        bls_ecfp_generate_pair(BLS_CURVE_256K1, &publicKey, &privateKey, NULL);
        bls_ecfp_get_public_component(&publicKey, result);
        result[0] = ((result[64] & 1) ? 0x03 : 0x02);
	bls_bip32_derive_secp256k1_public(result, dest2 + 32, 0x00000000);
	bls_bip32_derive_secp256k1_public(result, dest2 + 32, 0x00000000);
        for (i=0; i<sizeof(PUBLIC_KEY); i++) {
                if (result[i] != PUBLIC_KEY[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("BTC derive public ok\n");
        }
        else {
                bls_debug("Fail BTC derive public\n");
        }
        bls_set_return(result, 0);
}

