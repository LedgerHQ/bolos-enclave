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
#include <signal.h>
#include <errno.h>
#include "bolos.h"
#include "machine.h"
#include "moxie_swi_common.h"

#include "sodium.h"

#define DEBUG printf

/*
* crypto_secretbox_easy
* $r0 -- c unsigned char*
* $r1 -- m unsigned char*
* $r2 -- mlen unsigned long long
* $r3 -- n unsigned char*
* $r4 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_secretbox_easy(struct machine *mach) {
    uint8_t *c;
    uint8_t *m;
    uint32_t mlen = mach->cpu.regs[MOXIE_R2];
    uint8_t *n;
    uint8_t *k;
    uint32_t status = 1;

    c = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  mlen + crypto_secretbox_MACBYTES, true);
    if (c == NULL) {
        DEBUG("Invalid ciphertext\n");
        goto end;
    }
    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], mlen, false);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    n = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                  crypto_secretbox_NONCEBYTES, false);
    if (n == NULL) {
        DEBUG("Invalid nonce\n");
        goto end;
    }
    k = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                  crypto_secretbox_KEYBYTES, false);
    if (k == NULL) {
        DEBUG("Invalid key\n");
        goto end;
    }
    status = crypto_secretbox_easy(c, m, mlen, n, k);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_secretbox_open_easy
* $r0 -- m unsigned char*
* $r1 -- c unsigned char*
* $r2 -- clen unsigned long long
* $r3 -- n unsigned char*
* $r4 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_secretbox_open_easy(struct machine *mach) {
    uint8_t *m;
    uint8_t *c;
    uint32_t clen = mach->cpu.regs[MOXIE_R2];
    uint8_t *n;
    uint8_t *k;
    uint32_t status = 1;

    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  clen - crypto_secretbox_MACBYTES, true);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    c = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], clen, false);
    if (c == NULL) {
        DEBUG("Invalid ciphertext\n");
        goto end;
    }
    n = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                  crypto_secretbox_NONCEBYTES, false);
    if (n == NULL) {
        DEBUG("Invalid nonce\n");
        goto end;
    }
    k = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                  crypto_secretbox_KEYBYTES, false);
    if (k == NULL) {
        DEBUG("Invalid key\n");
        goto end;
    }
    status = crypto_secretbox_open_easy(m, c, clen, n, k);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_auth
* $r0 -- out unsigned char*
* $r1 -- in unsigned char*
* $r2 -- inlen unsigned long long
* $r3 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_auth(struct machine *mach) {
    uint8_t *out;
    uint8_t *in;
    uint32_t inlen = mach->cpu.regs[MOXIE_R2];
    uint8_t *k;
    uint32_t status = 1;

    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                    crypto_auth_BYTES, true);
    if (out == NULL) {
        DEBUG("Invalid MAC\n");
        goto end;
    }
    in =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], inlen, false);
    if (in == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    k = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                  crypto_auth_KEYBYTES, false);
    if (k == NULL) {
        DEBUG("Invalid key\n");
        goto end;
    }
    status = crypto_auth(out, in, inlen, k);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_auth_verify
* $r0 -- h unsigned char*
* $r1 -- in unsigned char*
* $r2 -- inlen unsigned long long
* $r3 -- k unsigned char*
* Output:
* int
*/
void moxie_crypto_auth_verify(struct machine *mach) {
    uint8_t *h;
    uint8_t *in;
    uint32_t inlen = mach->cpu.regs[MOXIE_R2];
    uint8_t *k;
    uint32_t status = 1;

    h = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  crypto_auth_BYTES, false);
    if (h == NULL) {
        DEBUG("Invalid MAC\n");
        goto end;
    }
    in =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], inlen, false);
    if (in == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    k = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                  crypto_auth_KEYBYTES, false);
    if (k == NULL) {
        DEBUG("Invalid key\n");
        goto end;
    }
    status = crypto_auth_verify(h, in, inlen, k);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_box_keypair
* $r0 -- pk unsigned char*
* $r1 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_keypair(struct machine *mach) {
    uint8_t *pk;
    uint8_t *sk;
    uint32_t status = 1;

    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                   crypto_box_PUBLICKEYBYTES, true);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }
    sk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1],
                                   crypto_box_SECRETKEYBYTES, true);
    if (sk == NULL) {
        DEBUG("Invalid private key\n");
        goto end;
    }
    status = crypto_box_keypair(pk, sk);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_box_easy
* $r0 -- c unsigned char*
* $r1 -- m unsigned char*
* $r2 -- mlen unsigned long long
* $r3 -- n unsigned char*
* $r4 -- pk unsigned char*
* $r5 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_easy(struct machine *mach) {
    uint8_t *c;
    uint8_t *m;
    uint32_t mlen = mach->cpu.regs[MOXIE_R2];
    uint8_t *n;
    uint8_t *pk;
    uint8_t *sk;
    uint32_t status = 1;

    c = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  mlen + crypto_box_MACBYTES, true);
    if (c == NULL) {
        DEBUG("Invalid ciphertext\n");
        goto end;
    }
    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], mlen, false);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    n = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                  crypto_box_NONCEBYTES, false);
    if (n == NULL) {
        DEBUG("Invalid nonce\n");
        goto end;
    }
    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                   crypto_box_PUBLICKEYBYTES, false);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }
    sk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R5],
                                   crypto_box_SECRETKEYBYTES, false);
    if (sk == NULL) {
        DEBUG("Invalid private key\n");
        goto end;
    }

    status = crypto_box_easy(c, m, mlen, n, pk, sk);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_box_open_easy
* $r0 -- m unsigned char*
* $r1 -- c unsigned char*
* $r2 -- clen unsigned long long
* $r3 -- n unsigned char*
* $r4 -- pk unsigned char*
* $r5 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_open_easy(struct machine *mach) {
    uint8_t *m;
    uint8_t *c;
    uint32_t clen = mach->cpu.regs[MOXIE_R2];
    uint8_t *n;
    uint8_t *pk;
    uint8_t *sk;
    uint32_t status = 1;

    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  clen - crypto_box_MACBYTES, true);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    c = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], clen, false);
    if (c == NULL) {
        DEBUG("Invalid ciphertext\n");
        goto end;
    }
    n = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                  crypto_box_NONCEBYTES, false);
    if (n == NULL) {
        DEBUG("Invalid nonce\n");
        goto end;
    }
    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                   crypto_box_PUBLICKEYBYTES, false);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }
    sk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R5],
                                   crypto_box_SECRETKEYBYTES, false);
    if (sk == NULL) {
        DEBUG("Invalid private key\n");
        goto end;
    }

    status = crypto_box_open_easy(m, c, clen, n, pk, sk);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_box_seal
* $r0 -- c unsigned char*
* $r1 -- m unsigned char*
* $r2 -- mlen unsigned long long
* $r3 -- pk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_seal(struct machine *mach) {
    uint8_t *c;
    uint8_t *m;
    uint32_t mlen = mach->cpu.regs[MOXIE_R2];
    uint8_t *pk;
    uint32_t status = 1;

    c = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  mlen + crypto_box_SEALBYTES, true);
    if (c == NULL) {
        DEBUG("Invalid ciphertext\n");
        goto end;
    }
    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], mlen, false);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                   crypto_box_PUBLICKEYBYTES, false);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }

    status = crypto_box_seal(c, m, mlen, pk);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_box_seal_open
* $r0 -- m unsigned char*
* $r1 -- c unsigned char*
* $r2 -- clen unsigned long long
* $r3 -- pk unsigned char*
* $r4 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_box_seal_open(struct machine *mach) {
    uint8_t *m;
    uint8_t *c;
    uint32_t clen = mach->cpu.regs[MOXIE_R2];
    uint8_t *pk;
    uint8_t *sk;
    uint32_t status = 1;

    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  clen - crypto_box_SEALBYTES, true);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    c = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], clen, false);
    if (c == NULL) {
        DEBUG("Invalid ciphertext\n");
        goto end;
    }
    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3],
                                   crypto_box_PUBLICKEYBYTES, false);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }
    sk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                   crypto_box_SECRETKEYBYTES, false);
    if (sk == NULL) {
        DEBUG("Invalid private key\n");
        goto end;
    }

    status = crypto_box_seal_open(m, c, clen, pk, sk);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_sign_keypair
* $r0 -- pk unsigned char*
* $r1 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_sign_keypair(struct machine *mach) {
    uint8_t *pk;
    uint8_t *sk;
    uint32_t status = 1;

    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                   crypto_sign_PUBLICKEYBYTES, true);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }
    sk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1],
                                   crypto_sign_SECRETKEYBYTES, true);
    if (sk == NULL) {
        DEBUG("Invalid private key\n");
        goto end;
    }
    status = crypto_sign_keypair(pk, sk);

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_sign
* $r0 -- sm unsigned char*
* $r1 -- smlen_p unsigned long long*
* $r2 -- m unsigned char*
* $r3 -- mlen unsigned long long
* $r4 -- sk unsigned char*
* Output:
* int
*/
void moxie_crypto_sign(struct machine *mach) {
    uint8_t *sm;
    uint8_t *m;
    uint32_t mlen = mach->cpu.regs[MOXIE_R3];
    uint8_t *sk;
    uint32_t status = 1;
    unsigned long long smlen_param;
    sm = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                   crypto_sign_BYTES + mlen, true);
    if (sm == NULL) {
        DEBUG("Invalid signature buffer\n");
        goto end;
    }
    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2], mlen, false);
    if (m == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    sk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                   crypto_sign_SECRETKEYBYTES, false);
    if (sk == NULL) {
        DEBUG("Invalid private key\n");
        goto end;
    }

    status = crypto_sign(sm, &smlen_param, m, mlen, sk);
    if (!write32_check(mach, mach->cpu.regs[MOXIE_R1], smlen_param)) {
        DEBUG("Invalid length pointer (write)\n");
        status = 0;
        goto end;
    }
    {
        uint32_t test = smlen_param;
        DEBUG("Sign writing size %d %d\n", test, crypto_sign_BYTES);
    }

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* crypto_sign_open
* $r0 -- m unsigned char*
* $r1 -- mlen_p unsigned long long*
* $r2 -- sm unsigned char*
* $r3 -- smlen unsigned long long
* $r4 -- pk unsigned char*
* Output:
* int
*/
void moxie_crypto_sign_open(struct machine *mach) {
    uint8_t *m;
    uint8_t *sm;
    uint32_t smlen = mach->cpu.regs[MOXIE_R3];
    uint8_t *pk;
    uint32_t status = 1;
    unsigned long long mlen_param;
    DEBUG("sign open %d\n", smlen);
    m = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                  smlen - crypto_sign_BYTES, true);
    if (m == NULL) {
        DEBUG("Invalid signature buffer\n");
        goto end;
    }
    sm =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R2], smlen, false);
    if (sm == NULL) {
        DEBUG("Invalid message\n");
        goto end;
    }
    pk = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R4],
                                   crypto_sign_PUBLICKEYBYTES, false);
    if (pk == NULL) {
        DEBUG("Invalid public key\n");
        goto end;
    }

    status = crypto_sign_open(m, &mlen_param, sm, smlen, pk);
    if (!write32_check(mach, mach->cpu.regs[MOXIE_R1], mlen_param)) {
        DEBUG("Invalid length pointer (write)\n");
        status = 0;
        goto end;
    }

end:
    mach->cpu.regs[MOXIE_R0] = status;
}
