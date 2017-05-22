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
 * @brief misc BOLOS utilities functions
 * @file bolos_utils.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Provide a set of utilities functions
 *
 */

#ifndef __BOLOS_UTILS_H__
#define __BOLOS_UTILS_H__

/**
 * @brief send debugging information to the Normal World
 *
 * @param [in] text string to send
 */
void bls_debug(const char *text);

#endif // __BOLOS_UTILS_H__
