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

#include "hexUtils.h"

int getNibble(char x) {
    if ((x >= '0') && (x <= '9')) {
        return (x - '0');
    }
    if ((x >= 'A') && (x <= 'F')) {
        return ((x - 'A') + 10);
    }
    if ((x >= 'a') && (x <= 'f')) {
        return ((x - 'a') + 10);
    }
    return -1;
}

size_t hexToBin(const char *data, unsigned char *out, size_t outLength) {
    int i;
    int length = strlen(data);
    if ((length % 2) != 0) {
        return 0;
    }
    if (outLength < (length / 2)) {
        return 0;
    }
    for (i = 0; i < length; i += 2) {
        int nibbleHigh = getNibble(data[i]);
        int nibbleLow = getNibble(data[i + 1]);
        if ((nibbleHigh < 0) || (nibbleLow < 0)) {
            return 0;
        }
        out[i / 2] = ((nibbleHigh << 4) | nibbleLow);
    }
    return (length / 2);
}

void displayBinary(unsigned char *buffer, size_t length) {
    size_t i;
    for (i = 0; i < length; i++) {
        printf("%.2x", buffer[i]);
    }
    printf("\n");
}
