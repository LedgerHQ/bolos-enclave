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
 * @brief User Interface functions for Bolos TEE
 * @file bolos_ui.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * The User Interface API let the executed code run simple primitives on the
 * Trusted UI.
 *
 * This API is specific to the Kinibi implementation due to memory limitations
 */

#ifndef __BOLOS_UI_H__
#define __BOLOS_UI_H__

/** UI is available */
#define BLS_UI_CAPS_AVAILABLE (1 << 0)
/** UI supports text displayed on several lines */
#define BLS_UI_CAPS_MULTILINE (1 << 1)
/** UI supports a touch screen */
#define BLS_UI_CAPS_TOUCH (1 << 2)
/** UI supports color */
#define BLS_UI_CAPS_COLOR (1 << 3)
/** UI supports user text input */
#define BLS_UI_CAPS_USER_ENTRY (1 << 4)
/** UI executes in the application thread */
#define BLS_UI_CAPS_INAPP (1 << 5)
/** UI can display a QR code */
#define BLS_UI_CAPS_QR (1 << 6)

/**
 * @brief Return the UI capabilities as a bitmask
 *
 * @return UI capabilities
 */
int bls_ui_get_capabilities(void);

/**
 * @brief Display a simple information message
 *
 * @param [in] text
 *   Text message to display
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_ui_display_message(const char WIDE *text);

/**
 * @brief Display a simple warning message
 *
 * @param [in] text
 *   Text message to display
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_ui_display_warning(const char WIDE *text);

/**
 * @brief Display a simple error
 *
 * @param [in] text
 *   Text message to display
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_ui_display_error(const char WIDE *text);

/**
 * @brief Display a OK/CANCEL choice message
 *
 * @param [in] message
 *   Text message to display
 *
 * @return 1 if OK was selected, 0 if CANCEL was selected or an error occurred
 *
 */
int bls_ui_display_choice(const char WIDE *message);

/**
 * @brief Display a QR code
 *
 * @param [in] message
 *   Text message to display
 *
 * @param [in] data
 *   Buffer to the data to display as a QR code
 *
 * @param [in] dataSize
 *   Size of the data to display as a QR code
 *
 * @return 1 if success, 0 if error
 *
 */
int bls_ui_display_qr(const char WIDE *message, const char WIDE *data,
                      size_t dataSize);

/**
 * @brief Retrieve user input
 *
 * @param [in] message
 *   Text message to display
 *
 * @param [out] out
 *   Buffer to contain the user data
 *
 * @param [in] outLength
 *   Size of the buffer to contain the user data
 *
 * @return size of the user data collected or 0 if an error occurrred
 *
 */
int bls_ui_get_user_entry(const char WIDE *message, char WIDE *out,
                          size_t outLength);

#endif // __BOLOS_UI_H__
