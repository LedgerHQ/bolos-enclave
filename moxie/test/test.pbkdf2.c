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

const unsigned char PASSWORD[] = "password";
const unsigned char SALT[] = "salt    ";
const unsigned char RESULT[] = { 0xe1, 0xd9, 0xc1, 0x6a, 0xa6, 0x81, 0x70, 0x8a, 0x45, 0xf5, 0xc7, 0xc4, 0xe2, 0x15, 0xce, 0xb6, 0x6e, 0x01, 0x1a, 0x2e, 0x9f, 0x00, 0x40, 0x71, 0x3f, 0x18, 0xae, 0xfd, 0xb8, 0x66, 0xd5, 0x3c, 0xf7, 0x6c, 0xab, 0x28, 0x68, 0xa3, 0x9b, 0x9f, 0x78, 0x40, 0xed, 0xce, 0x4f, 0xef, 0x5a, 0x82, 0xbe, 0x67, 0x33, 0x5c, 0x77, 0xa6, 0x06, 0x8e, 0x04, 0x11, 0x27, 0x54, 0xf2, 0x7c, 0xcf, 0x4e};

int main(int argc, char **argv) {
	uint32_t i;
	bls_area_t password;
	bls_area_t salt;
	unsigned char dest[64];
	uint8_t ok = 1;
	password.buffer = PASSWORD;
	password.length = 8;
	salt.buffer = SALT;
	salt.length = 8;
	bls_pbkdf2(BLS_SHA512, &password, &salt, 2, dest);
        for (i=0; i<sizeof(RESULT); i++) {
                if (dest[i] != RESULT[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("pbkdf2 ok\n");
        }
	else {
		bls_debug("pbkdf2 ko\n");
	}
}

