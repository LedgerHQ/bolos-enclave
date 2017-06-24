/*
*******************************************************************************
*   BOLOS TEE
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

/**
 * @brief BOLOS TEE general include file
 * @file bolos.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Include this file in your running code to use the BOLOS API on a Ledger TEE
 * implementation.
 *
 */

/**
\mainpage Introduction to BOLOS TEE

The Bitcoin Open Ledger Operating System (BOLOS) is Ledger platform allowing
developers to create pluggable applications on their Hardware Wallets.

BOLOS Trusted Execution Environment is an implementation for third party
security hardware such as GlobalPlatform TEE, SGX or HSMs exposing a common API
similar to the native Hardware Wallet API with a few specific extensions

BOLOS TEE offers a minimal common set of features for all platforms including
Hardware Wallets :

   - Basic cryptographic APIs (symmetric and asymmetric ciphers, hashes) in
bolos_crypto.h
   - Methods to verify the authenticity of the first level issuer in
bolos_attestation.h, when applicable
   - Methods to verify the authenticity of the platform and running code code in
bolos_endorsement.h
   - Methods to share transient memory between different applications in
bolos_sharedmemory.h
   - Methods to perform low level BIP 32 derivations in bolos_bip32.h

The implementation of BOLOS for a Trusted Execution Environment also features
dedicated APIs :

   - Methods to exchange data between sessions and bind data to applications in
bolos_wrapping.h
   - Specific interface calls for a virtualized platform in bolos_core.h and
bolos_utils.h
   - New generation cryptographic primitives with NaCl / libsodium in
bolos_sodium.h
   - Implementation of anti replay counters in bolos_antireplay.h
   - Methods to access an optionally secure time source in bolos_time.h
   - Methods to temporarily halt the execution of an application until an I/O
event occurs in bolos_continuation.h

On platforms already exposing a Bitcoin wallet to the user, a few APIs are
offered to interact with it :

   - Access to the main Hierarchical Deterministic wallet of the user in
bolos_wallet.h
   - Simple User Interface (when a Trusted User Interface is available) in
bolos_ui.h

 On third party devices, BOLOS isolation is achieved by running a Moxie Virtual
CPU - for more details about setting
 up the environment, refer to https://github.com/LedgerHQ/bolos-tee
*/

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define WIDE const

#ifdef __MOXIE__
#ifndef __MOXIE_LITTLE_ENDIAN__
#error BOLOS requires a little endian moxie toolchain
#endif
#endif

#include "bolos_core.h"
#include "bolos_crypto_common.h"
#include "bolos_crypto_platform_tee.h"
#include "bolos_crypto.h"
#include "bolos_wrapping.h"
#include "bolos_attestation.h"
#include "bolos_endorsement.h"
#include "bolos_antireplay.h"
#include "bolos_sharedmemory.h"
#include "bolos_time.h"
#include "bolos_continuation.h"
#include "bolos_utils.h"
#include "bolos_bip32.h"
#include "bolos_wallet.h"
#include "bolos_ui.h"

#include "bolos_sodium.h"
