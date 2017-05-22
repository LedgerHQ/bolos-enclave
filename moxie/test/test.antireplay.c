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

#define ACTION_INCREASE 0x01
#define ACTION_DELETE 0x02

int main(int argc, char **argv) {
	unsigned char tmp[100];
	uint32_t refSize;
	uint8_t action;
 	bls_copy_input_parameters(tmp, 0, 2);
	action = tmp[0];
	refSize = tmp[1];
	if (refSize == 0) {
		refSize = bls_antireplay_create(tmp, sizeof(tmp));
		if (refSize == 0) {
			bls_debug("Failed to create antireplay\n");
			return 0;
		}
		bls_set_return(tmp, refSize);
	}
	else {
		uint32_t counter1, counter2;
		bls_copy_input_parameters(tmp, 2, refSize);
		if (action == ACTION_DELETE) {
			if (!bls_antireplay_delete(tmp, refSize)) {
				bls_debug("Failed to delete counter\n");
			}
			else {
				bls_debug("Counter deleted\n");
			}
			return 0;
		}
		if (!bls_antireplay_query(tmp, refSize, &counter1)) {
			bls_debug("Failed to query counter 1\n");
			return 0;
		}
		if (!bls_antireplay_increase(tmp, refSize)) {
			bls_debug("Failed to increase counter\n");
		}
		if (!bls_antireplay_query(tmp, refSize, &counter2)) {
			bls_debug("Failed to query counter 2\n");
			return 0;
		}
		if (counter2 != counter1 + 1) {
			bls_debug("Inconsistent counter2 value\n");
			return 0;
		}
		tmp[0] = counter2 >> 24;
		tmp[1] = counter2 >> 16;
		tmp[2] = counter2 >> 8;
		tmp[3] = counter2;
		bls_set_return(tmp, 4);
	}
}

