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

int main(int argc, char **argv) {
	unsigned char tmp[100];
	uint32_t refSize;
	uint64_t delta;
	uint8_t trusted;
	uint8_t action;
 	bls_copy_input_parameters(tmp, 0, 1);
	refSize = tmp[0];
	for (uint32_t i=0; i<32; i++) {
		tmp[i] = 0;
	}
	if (refSize != 0) {
		bls_copy_input_parameters(tmp, 1, refSize);
	}
	else {
		refSize = 32;
	}
	if (!bls_time_delta(tmp, refSize, &delta, &trusted)) {
		bls_debug("Failed to get delta time\n");
		return 0;
	}
        tmp[32] = trusted;
        tmp[33] = delta >> 56;
        tmp[34] = delta >> 48;
        tmp[35] = delta >> 40;
        tmp[36] = delta >> 32;
        tmp[37] = delta >> 24;
        tmp[38] = delta >> 16;
        tmp[39] = delta >> 8;
        tmp[40] = delta;

	bls_set_return(tmp, 32 + 1 + 8); 
}		

