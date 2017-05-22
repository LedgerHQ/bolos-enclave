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

const unsigned char TEST[] = "Hi There";
const unsigned char KEY[] = { 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
const unsigned char SHA256[] = { 0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7 }; 
const unsigned char SHA512[] = { 0x87,0xaa,0x7c,0xde,0xa5,0xef,0x61,0x9d,0x4f,0xf0,0xb4,0x24,0x1a,0x1d,0x6c,0xb0,0x23,0x79,0xf4,0xe2,0xce,0x4e,0xc2,0x78,0x7a,0xd0,0xb3,0x05,0x45,0xe1,0x7c,0xde,0xda,0xa8,0x33,0xb7,0xd6,0xb8,0xa7,0x02,0x03,0x8b,0x27,0x4e,0xae,0xa3,0xf4,0xe4,0xbe,0x9d,0x91,0x4e,0xeb,0x61,0xf1,0x70,0x2e,0x69,0x6c,0x20,0x3a,0x12,0x68,0x54 };

const unsigned char HEX[] = "0123456789ABCDEF";

void dump(unsigned char *buffer, int size) {
	uint32_t i;
	for (i=0; i<size; i++) {
		unsigned char tmp[3];
		unsigned char x = buffer[i];
		tmp[0] = HEX[(x >> 4) & 0x0f];
		tmp[1] = HEX[x & 0x0f];
		tmp[2] = '\0';
		bls_debug(tmp);
	}
}

int main(int argc, char **argv) {
	uint32_t i;
	unsigned char ok = 1;
	unsigned char destBuffer[100];
	bls_hmac_sha256_t sha256;
	bls_hmac_sha512_t sha512;
	bls_hmac_sha256_init(&sha256, KEY, sizeof(KEY));
	bls_hmac((bls_hmac_t*)&sha256, 0, TEST, 6, destBuffer);
	bls_hmac((bls_hmac_t*)&sha256, BLS_LAST, TEST + 6, 2, destBuffer); 
	dump(destBuffer, sizeof(SHA256));
	bls_debug("\n");
	for (i=0; i<sizeof(SHA256); i++) {
		if (destBuffer[i] != SHA256[i]) {
			ok = 0;
			break;
		}
	}
	if (ok) {
		bls_debug("SHA256 ok\n");
	}
	else {
		bls_debug("SHA256 ko\n");
	}
 	ok = 1;
        bls_hmac_sha512_init(&sha512, KEY, sizeof(KEY));
        bls_hmac((bls_hmac_t*)&sha512, 0, TEST, 6, destBuffer);
        bls_hmac((bls_hmac_t*)&sha512, BLS_LAST, TEST + 6, 2, destBuffer);
	dump(destBuffer, sizeof(SHA512));
	bls_debug("\n");
        for (i=0; i<sizeof(SHA512); i++) {
                if (destBuffer[i] != SHA512[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("SHA512 ok\n");
        }
	else {
		bls_debug("SHA512 ko\n");
	}
}

