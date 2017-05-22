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

#ifndef __PORTABLE_CX_H__

#define __PORTABLE_CX_H__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

enum cx_curve_e {
  CX_CURVE_NONE,
  CX_CURVE_256K1,
  CX_CURVE_256R1,
  CX_CURVE_192K1,
  CX_CURVE_192R1,
};
typedef enum cx_curve_e cx_curve_t;

struct cx_ecfp_public_key_s{
  cx_curve_t   curve;
  int           W_len;
  unsigned char W[65];
};

struct cx_ecfp_private_key_s{
  cx_curve_t   curve;
  int           d_len;
  unsigned char d[32];
};

typedef struct cx_ecfp_public_key_s cx_ecfp_public_key_t;
typedef struct cx_ecfp_private_key_s cx_ecfp_private_key_t;

#endif
