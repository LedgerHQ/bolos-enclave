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

const unsigned char TEST[] = "test message";
const unsigned char RIPEMD160[] = { 0x5c,0xb3,0x2c,0x65,0x1c,0x51,0xcf,0xf4,0x1e,0x32,0x0e,0x96,0x73,0x8b,0xb1,0xec,0xd0,0xc5,0xb3,0x15 };
const unsigned char SHA1[] = { 0x35,0xee,0x83,0x86,0x41,0x0d,0x41,0xd1,0x4b,0x3f,0x77,0x9f,0xc9,0x5f,0x46,0x95,0xf4,0x85,0x16,0x82 };
const unsigned char SHA256[] = { 0x3f,0x0a,0x37,0x7b,0xa0,0xa4,0xa4,0x60,0xec,0xb6,0x16,0xf6,0x50,0x7c,0xe0,0xd8,0xcf,0xa3,0xe7,0x04,0x02,0x5d,0x4f,0xda,0x3e,0xd0,0xc5,0xca,0x05,0x46,0x87,0x28 };
const unsigned char SHA512[] = { 0x95,0x0b,0x2a,0x7e,0xff,0xa7,0x8f,0x51,0xa6,0x35,0x15,0xec,0x45,0xe0,0x3e,0xce,0xbe,0x50,0xef,0x2f,0x1c,0x41,0xe6,0x96,0x29,0xb5,0x07,0x78,0xf1,0x1b,0xc0,0x80,0x00,0x2e,0x4d,0xb8,0x11,0x2b,0x59,0xd0,0x93,0x89,0xd1,0x0f,0x35,0x58,0xf8,0x5b,0xfd,0xeb,0x4f,0x1c,0xc5,0x5a,0x34,0x21,0x7a,0xf0,0xf8,0x54,0x77,0x00,0xeb,0xf3 };
const unsigned char KECCAK256[] = { 0xea,0x83,0xcd,0xcd,0xd0,0x6b,0xf6,0x1e,0x41,0x40,0x54,0x11,0x5a,0x55,0x1e,0x23,0x13,0x37,0x11,0xd0,0x50,0x7d,0xcb,0xc0,0x7a,0x4b,0xab,0x7d,0xc4,0x58,0x19,0x35 };

int main(int argc, char **argv) {
	uint32_t i;
	unsigned char ok = 1;
	unsigned char destBuffer[100];
	bls_sha256_t sha256;
	bls_sha1_t sha1;
	bls_sha512_t sha512;
	bls_sha3_t sha3;
	bls_ripemd160_t ripemd160;
	bls_sha256_init(&sha256);
	bls_hash(&sha256.header, 0, TEST, 10, destBuffer);
	bls_hash(&sha256.header, BLS_LAST, TEST + 10, 2, destBuffer); 
	for (i=0; i<sizeof(SHA256); i++) {
		if (destBuffer[i] != SHA256[i]) {
			ok = 0;
			break;
		}
	}
	if (ok) {
		bls_debug("SHA256 ok\n");
	}
 	ok = 1;
        bls_sha512_init(&sha512);
        bls_hash(&sha512.header, 0, TEST, 10, destBuffer);
        bls_hash(&sha512.header, BLS_LAST, TEST + 10, 2, destBuffer);
        for (i=0; i<sizeof(SHA512); i++) {
                if (destBuffer[i] != SHA512[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("SHA512 ok\n");
        }
	ok = 1;
	bls_keccak_init(&sha3, 256);
        bls_hash(&sha3.header, 0, TEST, 10, destBuffer);
        bls_hash(&sha3.header, BLS_LAST, TEST + 10, 2, destBuffer);
        for (i=0; i<sizeof(KECCAK256); i++) {
                if (destBuffer[i] != KECCAK256[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("KECCAK-256 ok\n");
        }
	ok = 1;
        bls_ripemd160_init(&ripemd160);
	/*
        bls_hash(&ripemd160.header, 0, TEST, 10, destBuffer);
        bls_hash(&ripemd160.header, BLS_LAST, TEST + 10, 2, destBuffer);
	*/
	bls_hash(&ripemd160.header, BLS_LAST, TEST, 12, destBuffer);
        for (i=0; i<sizeof(RIPEMD160); i++) {
                if (destBuffer[i] != RIPEMD160[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("RIPEMD160 ok\n");
        }
	else {
		bls_debug("RIPEMD160 ko\n");
	}
	ok = 1;
        bls_sha1_init(&sha1);
        bls_hash(&sha1.header, 0, TEST, 10, destBuffer);
        bls_hash(&sha1.header, BLS_LAST, TEST + 10, 2, destBuffer);
        for (i=0; i<sizeof(SHA1); i++) {
                if (destBuffer[i] != SHA1[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("SHA1 ok\n");
        }
	else {
		bls_debug("SHA1 ko\n");
	}


}

