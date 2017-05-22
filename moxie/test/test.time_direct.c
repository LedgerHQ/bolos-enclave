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
	uint64_t value;
	uint8_t trusted;
	uint8_t result[9];
	if (!bls_time_supported()) {
		bls_debug("Time APIs not supported\n");
		return 0;
	}
	bls_time(&value, &trusted);
	result[0] = trusted;
	result[1] = value >> 56;
	result[2] = value >> 48;
	result[3] = value >> 40;
	result[4] = value >> 32;
	result[5] = value >> 24;
	result[6] = value >> 16;
	result[7] = value >> 8;	
	result[8] = value;
	bls_set_return(result, 9);
}

