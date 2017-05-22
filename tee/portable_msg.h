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

#ifndef __OS_MSG_H__

#define __OS_MSG_H__

#define CMD_SESSION_OPEN 0x0001
#define CMD_SESSION_CLOSE 0x0002
#define CMD_GET_PLATFORM_ID 0x0003
#define CMD_PROVIDE_TOKEN 0x0004
#define CMD_GET_VERSION 0x0005

#define CMD_CODE_INIT 0x0101
#define CMD_CODE_LOAD_SECTION 0x0102
#define CMD_CODE_RUN 0x0103
#define CMD_CODE_RESUME 0x0104

#define MSG_LOAD_SECTION_FLAG_READ_ONLY 0x01

typedef struct coderuntime_init_query_s {
    unsigned int loadSize;
} coderuntime_init_query_t;

typedef struct coderuntime_load_section_query_s {
    unsigned char flags;
    unsigned int sectionStart;
    unsigned int sectionEnd;
    unsigned int sectionDataLength;
} coderuntime_load_section_query_t;

typedef struct coderuntime_run_code_query_s {
    unsigned int entryPoint;
    unsigned int stackSize;
    unsigned int uiDataLength;
    unsigned int inputDataLength;
    unsigned int signatureLength;
} coderuntime_run_code_query_t;

typedef struct coderuntime_resume_code_query_s {
    unsigned int slot;
    unsigned int stateBlobSize;
    unsigned int uiDataLength;
    unsigned int inputDataLength;
} coderuntime_resume_code_query_t;

#define STATUS_CODE_EXEC_OK 0x01
#define STATUS_CODE_EXEC_ERROR 0x80
#define STATUS_CODE_EXEC_LOG 0x02
#define STATUS_CODE_EXEC_SUSPENDED 0x03

#endif
