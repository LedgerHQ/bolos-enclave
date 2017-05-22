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
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include "portable_msg.h"
#include "hexUtils.h"
#include "client_al.h"

//#define DEFAULT_STACK_SIZE 2048
#define DEFAULT_STACK_SIZE 100000

#define SUSPEND_FILE "suspend.bin"

#define LEDGER_SIGNATURE ".ledger"

#ifndef EM_MOXIE
#define EM_MOXIE 223 /* Official Moxie */
#endif               // EM_MOXIE

#ifndef EM_MOXIE_OLD
#define EM_MOXIE_OLD 0xFEED /* Old Moxie */
#endif                      // EM_MOXIE_OLD

void write16BE(uint8_t *buffer, uint32_t data) {
    buffer[0] = ((data >> 8) & 0xff);
    buffer[1] = (data & 0xff);
}

void write32BE(uint8_t *buffer, uint32_t data) {
    buffer[0] = ((data >> 24) & 0xff);
    buffer[1] = ((data >> 16) & 0xff);
    buffer[2] = ((data >> 8) & 0xff);
    buffer[3] = (data & 0xff);
}

uint32_t read32BE(uint8_t *buffer) {
    return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
}

uint8_t *parseBinaryParameter(char *parameter, uint32_t *size) {
    uint8_t *result;
    if ((strlen(parameter) % 2) != 0) {
        fprintf(stderr, "Invalid length for %s\n", parameter);
        return NULL;
    }
    *size = strlen(parameter) / 2;
    result = (uint8_t *)malloc(*size);
    if (result == NULL) {
        fprintf(stderr, "Failed to allocate memory for %s\n", parameter);
        return NULL;
    }
    if (hexToBin(parameter, result, *size) != *size) {
        fprintf(stderr, "Invalid data %s\n", parameter);
        free(result);
        return NULL;
    }
    return result;
}

void usage(char *name) {
    fprintf(stderr, "Usage : %s command with the following commands\n", name);
    fprintf(stderr, "\tload [elf] [(parameters hex, default none)] [(stack "
                    "size, default %d)] : load and execute the given code\n",
            DEFAULT_STACK_SIZE);
    fprintf(stderr, "\ttokenload [elf] [local key] [id] [token] [(parameters "
                    "hex, default none)] [(stack size, default %d)] : load and "
                    "execute the given code using the given token\n",
            DEFAULT_STACK_SIZE);
    fprintf(stderr, "\tresume [elf] [slot] [(parameters hex, default none)] : "
                    "resume execution from previously saved %s\n",
            SUSPEND_FILE);
    fprintf(stderr, "\tid : returns the Platform ID when available\n");
    platform_usage(name);
}

int process(void *context, int argc, char **argv) {
    uint8_t *buffer;
    uint8_t responseBuffer[200000];
    uint8_t signature[100];
    Elf *elfFile;
    GElf_Ehdr elfMainHeader;
    Elf_Scn *scn;
    size_t elfProgramSize;
    size_t i;
    size_t stringIndexSize;
    uint32_t recvLen;
    uint32_t stackSize = DEFAULT_STACK_SIZE;
    uint32_t allocateSize = 0;
    uint8_t *parameters = NULL;
    uint32_t parametersSize = 0;
    uint8_t *token = NULL;
    uint32_t tokenSize = 0;
    uint8_t *id = NULL;
    uint32_t idSize = 0;
    uint8_t *localKey = NULL;
    uint32_t localKeySize = 0;
    uint8_t *resumeData = NULL;
    uint32_t resumeDataSize = 0;
    uint32_t slot = 0;
    int fd = 0;
    int offset;
    uint32_t bufferLength;
#ifdef ELF_IN_MEMORY
    FILE *elfData;
    uint8_t *elfContent = NULL;
    uint32_t elfSize;
#endif

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcasecmp(argv[1], "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Missing file name\n");
            return 1;
        }
        if (argc >= 4) {
            parameters = parseBinaryParameter(argv[3], &parametersSize);
            if (!parameters) {
                goto error3;
            }
        }
        if (argc >= 5) {
            stackSize = atoi(argv[4]);
            if (stackSize == 0) {
                fprintf(stderr, "Invalid stack size\n");
                goto error3;
            }
        }
    } else if (strcasecmp(argv[1], "tokenload") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Missing file name\n");
            return 1;
        }
        if (argc < 4) {
            fprintf(stderr, "Missing key\n");
            return 1;
        }
        localKey = parseBinaryParameter(argv[3], &localKeySize);
        if (!localKey) {
            goto error3;
        }
        if (argc < 5) {
            fprintf(stderr, "Missing id\n");
            return 1;
        }
        id = parseBinaryParameter(argv[4], &idSize);
        if (!id) {
            goto error3;
        }
        if (argc < 6) {
            fprintf(stderr, "Missing token\n");
            return 1;
        }
        token = parseBinaryParameter(argv[5], &tokenSize);
        if (!token) {
            goto error3;
        }
        if (argc >= 7) {
            parameters = parseBinaryParameter(argv[6], &parametersSize);
            if (!parameters) {
                goto error3;
            }
        }
        if (argc >= 8) {
            stackSize = atoi(argv[7]);
            if (stackSize == 0) {
                fprintf(stderr, "Invalid stack size\n");
                goto error3;
            }
        }
    } else if (strcasecmp(argv[1], "id") == 0) {
        // Get ID

        bufferLength = 2;
        buffer = (uint8_t *)malloc(bufferLength);
        write16BE(buffer, CMD_GET_PLATFORM_ID);
        recvLen = platform_exchange(context, buffer, bufferLength,
                                    responseBuffer, sizeof(responseBuffer));
        free(buffer);
        if ((recvLen < 1) || (responseBuffer[0] != STATUS_CODE_EXEC_OK)) {
            fprintf(stderr, "Get Platform ID returned error 0x%x\n",
                    responseBuffer[0]);
            goto error;
        }
        printf("ID : ");
        for (i = 0; i < recvLen - 1; i++) {
            printf("%.2x", responseBuffer[i + 1]);
        }
        printf("\n");

        return 0;
    } else if (strcasecmp(argv[1], "resume") == 0) {
        FILE *suspendFile;
        if (argc < 3) {
            fprintf(stderr, "Missing slot\n");
            return 1;
        }
        if (argc < 4) {
            fprintf(stderr, "Missing file name\n");
            return 1;
        }
        slot = atoi(argv[3]);
        suspendFile = fopen(SUSPEND_FILE, "rb");
        if (suspendFile == NULL) {
            fprintf(stderr, "No resume data available\n");
            return 1;
        }
        fseek(suspendFile, 0, SEEK_END);
        resumeDataSize = ftell(suspendFile);
        fseek(suspendFile, 0, SEEK_SET);
        resumeData = (uint8_t *)malloc(resumeDataSize);
        fread(resumeData, 1, resumeDataSize, suspendFile);
        fclose(suspendFile);
        if (argc >= 5) {
            parameters = parseBinaryParameter(argv[4], &parametersSize);
            if (!parameters) {
                goto error3;
            }
        }
    } else {
        fprintf(stderr, "Unsupported command\n");
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "Failed to initialize ELF parsing library\n");
        goto error3;
    }

#ifndef ELF_IN_MEMORY
    fd = open(argv[2], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open ELF %s\n", argv[2]);
        goto error3;
    }

    elfFile = elf_begin(fd, ELF_C_READ, NULL);
#else
    fopen_s(&elfData, argv[2], "rb");
    fseek(elfData, 0, SEEK_END);
    elfSize = ftell(elfData);
    fseek(elfData, 0, SEEK_SET);
    elfContent = (uint8_t *)malloc(elfSize);
    fread(elfContent, 1, elfSize, elfData);
    fclose(elfData);
    elfFile = elf_memory((char *)elfContent, elfSize);
#endif

    if (elf_kind(elfFile) != ELF_K_ELF) {
        fprintf(stderr, "Invalid ELF file\n");
        goto error;
    }
    if (gelf_getehdr(elfFile, &elfMainHeader) != &elfMainHeader) {
        fprintf(stderr, "Failed to parse ELF main header\n");
        goto error;
    }
    if ((elfMainHeader.e_ident[EI_CLASS] != ELFCLASS32) ||
        (elfMainHeader.e_ident[EI_DATA] != ELFDATA2LSB) ||
        ((elfMainHeader.e_machine != EM_MOXIE) &&
         (elfMainHeader.e_machine != EM_MOXIE_OLD))) {
        fprintf(stderr, "Usupported ELF binary type\n");
        goto error;
    }

#ifndef GNU_LIBELF
    if (elf_getshdrstrndx(elfFile, &stringIndexSize) != 0) {
        fprintf(stderr, "Failed to retrieve string index size\n");
        goto error;
    }
    if (elf_getphdrnum(elfFile, &elfProgramSize) != 0) {
        fprintf(stderr, "Error reading number of ELF program headers\n");
        goto error;
    }
#else
    stringIndexSize = elfMainHeader.e_shstrndx;
    elfProgramSize = elfMainHeader.e_phnum;
#endif

    // Get the signature
    scn = NULL;
    memset(signature, 0, sizeof(signature));
    while ((scn = elf_nextscn(elfFile, scn)) != NULL) {
        GElf_Shdr sectionHeader;
        char *name;
        if (gelf_getshdr(scn, &sectionHeader) != &sectionHeader) {
            fprintf(stderr, "Failed to read section header\n");
            goto error;
        }
        name = elf_strptr(elfFile, stringIndexSize, sectionHeader.sh_name);
        if (name != NULL) {
            if (strcmp(name, LEDGER_SIGNATURE) == 0) {
                Elf_Data *data = NULL;
                offset = 0;
                while (offset < sectionHeader.sh_size) {
                    data = elf_getdata(scn, data);
                    if (data == NULL) {
                        break;
                    }
                    if ((offset + data->d_size) > sizeof(signature)) {
                        fprintf(stderr, "Failed to parse signature\n");
                        goto error;
                    }
                    memcpy(signature + offset, data->d_buf, data->d_size);
                    offset += data->d_size;
                }
                break;
            }
        }
    }
    if (signature[0] == 0) {
        fprintf(stderr, "Code signature not found\n");
        goto error;
    }

    // Compute size to allocate
    for (i = 0; i < elfProgramSize; i++) {
        GElf_Phdr elfHeader;
        if (gelf_getphdr(elfFile, i, &elfHeader) != &elfHeader) {
            fprintf(stderr, "Failed to parse ELF program header %ld\n", i);
            goto error;
        }
        if (elfHeader.p_type != PT_LOAD) {
            continue;
        }
        allocateSize += elfHeader.p_memsz;
    }
    allocateSize += stackSize;

    // Send token if present

    if ((localKey != NULL) && (id != NULL) && (token != NULL)) {
        bufferLength = 2 + 65 + 4 + 4 + tokenSize + idSize;
        buffer = (uint8_t *)malloc(bufferLength);
        offset = 0;
        write16BE(buffer + offset, CMD_PROVIDE_TOKEN);
        offset += 2;
        memcpy(buffer + offset, localKey, 65);
        offset += 65;
        write32BE(buffer + offset, idSize);
        offset += 4;
        write32BE(buffer + offset, tokenSize);
        offset += 4;
        memcpy(buffer + offset, id, idSize);
        offset += idSize;
        memcpy(buffer + offset, token, tokenSize);

        recvLen = platform_exchange(context, buffer, bufferLength,
                                    responseBuffer, sizeof(responseBuffer));
        free(buffer);
        if ((recvLen < 1) || (responseBuffer[0] != STATUS_CODE_EXEC_OK)) {
            fprintf(stderr, "ProvideToken returned error 0x%x\n",
                    responseBuffer[0]);
            goto error;
        }
    }

    // Init

    bufferLength = (2 + 4);
    buffer = (uint8_t *)malloc(bufferLength);
    write16BE(buffer, CMD_CODE_INIT);
    write32BE(buffer + 2, allocateSize);

    recvLen = platform_exchange(context, buffer, bufferLength, responseBuffer,
                                sizeof(responseBuffer));
    free(buffer);
    if ((recvLen < 1) || (responseBuffer[0] != STATUS_CODE_EXEC_OK)) {
        fprintf(stderr, "CodeInit returned error 0x%x\n", responseBuffer[0]);
        goto error;
    }

    for (i = 0; i < elfProgramSize; i++) {
        offset = 0;
        uint8_t flag = 0;
        GElf_Phdr elfHeader;
        if (gelf_getphdr(elfFile, i, &elfHeader) != &elfHeader) {
            fprintf(stderr, "Failed to parse ELF program header %ld\n", i);
            goto error;
        }
        if (elfHeader.p_type != PT_LOAD) {
            continue;
        }
        if (((elfHeader.p_flags & PF_W) == 0)) {
            flag |= 0x01;
        }

        bufferLength = 2 + 1 + 4 + 4 + 4 + elfHeader.p_filesz;
        buffer = (uint8_t *)malloc(bufferLength);
        write16BE(buffer + offset, CMD_CODE_LOAD_SECTION);
        offset += 2;
        buffer[offset++] = flag;
        write32BE(buffer + offset, elfHeader.p_vaddr);
        offset += 4;
        write32BE(buffer + offset, elfHeader.p_vaddr + elfHeader.p_memsz);
        offset += 4;
        write32BE(buffer + offset, elfHeader.p_filesz);
        offset += 4;
#ifndef ELF_IN_MEMORY
        off_t current = lseek(fd, 0, SEEK_CUR);
        uint32_t fileOffset = 0;
        lseek(fd, elfHeader.p_offset, SEEK_SET);
        while (fileOffset != elfHeader.p_filesz) {
            uint8_t tmp[4096];
            uint32_t chunkSize = (fileOffset + sizeof(tmp) > elfHeader.p_filesz
                                      ? elfHeader.p_filesz - fileOffset
                                      : sizeof(tmp));
            if (read(fd, tmp, chunkSize) != chunkSize) {
                fprintf(stderr, "Failed to read ELF data\n");
                goto error;
            }
            memcpy(buffer + offset, tmp, chunkSize);
            fileOffset += chunkSize;
            offset += chunkSize;
        }
        lseek(fd, current, SEEK_SET);
#else
        memcpy(buffer + offset, elfContent + elfHeader.p_offset,
               elfHeader.p_filesz);
        offset += elfHeader.p_filesz;
#endif

        recvLen = platform_exchange(context, buffer, bufferLength,
                                    responseBuffer, sizeof(responseBuffer));
        free(buffer);
        if ((recvLen < 1) || (responseBuffer[0] != STATUS_CODE_EXEC_OK)) {
            fprintf(stderr, "CodeLoad returned error 0x%x\n",
                    responseBuffer[0]);
            goto error;
        }
    }

    if (resumeData == NULL) {
        offset = 0;
        bufferLength =
            2 + 4 + 4 + 4 + 4 + 4 + parametersSize + signature[1] + 2;
        buffer = (uint8_t *)malloc(bufferLength);
        write16BE(buffer + offset, CMD_CODE_RUN);
        offset += 2;
        write32BE(buffer + offset, elfMainHeader.e_entry);
        offset += 4;
        write32BE(buffer + offset, stackSize);
        offset += 4;
        write32BE(buffer + offset, 0); // uiDataLength
        offset += 4;
        write32BE(buffer + offset, parametersSize);
        offset += 4;
        write32BE(buffer + offset, signature[1] + 2);
        offset += 4;
        memcpy(buffer + offset, parameters, parametersSize);
        offset += parametersSize;
        memcpy(buffer + offset, signature, signature[1] + 2);
        offset += signature[1] + 2;
    } else {
        offset = 0;
        bufferLength = 2 + 4 + 4 + 4 + 4 + resumeDataSize + parametersSize;
        buffer = (uint8_t *)malloc(bufferLength);
        write16BE(buffer + offset, CMD_CODE_RESUME);
        offset += 2;
        write32BE(buffer + offset, slot);
        offset += 4;
        write32BE(buffer + offset, resumeDataSize);
        offset += 4;
        write32BE(buffer + offset, 0); // uiDataLength
        offset += 4;
        write32BE(buffer + offset, parametersSize);
        offset += 4;
        memcpy(buffer + offset, resumeData, resumeDataSize);
        offset += resumeDataSize;
        memcpy(buffer + offset, parameters, parametersSize);
        offset += parametersSize;
    }

    recvLen = platform_exchange(context, buffer, bufferLength, responseBuffer,
                                sizeof(responseBuffer));
    free(buffer);
    if (recvLen < 1) {
        fprintf(stderr, "CodeRun returned no status\n");
        goto error;
    }
    switch (responseBuffer[0]) {
    case STATUS_CODE_EXEC_OK:
        printf("OK\n");
        for (i = 0; i < recvLen - 1; i++) {
            printf("%.2x", responseBuffer[i + 1]);
        }
        printf("\n");
        break;
    case STATUS_CODE_EXEC_ERROR:
        printf("ERROR\n");
        for (i = 0; i < recvLen - 1; i++) {
            printf("%.2x", responseBuffer[i + 1]);
        }
        printf("\n");
        break;
    case STATUS_CODE_EXEC_LOG:
        printf("LOG\n");
        responseBuffer[recvLen - 1] = '\0';
        printf("%s\n", responseBuffer + 1);
        break;
    case STATUS_CODE_EXEC_SUSPENDED: {
        uint32_t slot;
        uint32_t blobSize;
        uint32_t appDataSize;
        FILE *suspendFile;
        printf("SUSPENDED\n");
        if ((recvLen - 1) < (4 + 4 + 4)) {
            printf("Invalid response header size\n");
            break;
        }
        slot = read32BE(responseBuffer + 1);
        blobSize = read32BE(responseBuffer + 1 + 4);
        appDataSize = read32BE(responseBuffer + 1 + 4 + 4);
        if ((recvLen - 1) != (4 + 4 + 4 + blobSize + appDataSize)) {
            printf("Invalid response size\n");
            break;
        }
        printf("Slot %d\n", slot);
        suspendFile = fopen(SUSPEND_FILE, "wb");
        fwrite(responseBuffer + 1 + 4 + 4 + 4, 1, blobSize, suspendFile);
        fclose(suspendFile);
        printf("Application data : ");
        for (i = 0; i < appDataSize; i++) {
            printf("%.2x", responseBuffer[1 + 4 + 4 + 4 + blobSize + i]);
        }
        printf("\n");
    } break;
    default:
        fprintf(stderr, "CodeRun returned error 0x%x\n", responseBuffer[0]);
        goto error;
    }

#ifndef ELF_IN_MEMORY
    close(fd);
#else
    free(elfContent);
#endif

    if (parameters != NULL) {
        free(parameters);
    }
    if (token != NULL) {
        free(token);
    }
    if (id != NULL) {
        free(id);
    }
    if (localKey != NULL) {
        free(localKey);
    }
    if (resumeData != NULL) {
        free(resumeData);
    }
    return 0;

error:
#ifndef ELF_IN_MEMORY
    if (fd != 0) {
        close(fd);
    }
#else
    if (elfContent != NULL) {
        free(elfContent);
    }
#endif
error3:
    if (parameters != NULL) {
        free(parameters);
    }
    if (token != NULL) {
        free(token);
    }
    if (id != NULL) {
        free(id);
    }
    if (localKey != NULL) {
        free(localKey);
    }
    if (resumeData != NULL) {
        free(resumeData);
    }
    return 1;
}

int main(int argc, char **argv) {
    void *context;
    int result = 1;
    uint8_t *buffer;
    uint8_t responseBuffer[4096];
    uint32_t bufferLength;
    uint32_t recvLen;

    context = platform_init();
    if (context == NULL) {
        fprintf(stderr, "Failed to initialize platform\n");
        goto error;
    }

    // Open Session

    bufferLength = 2 + 4 + 4;
    buffer = (uint8_t *)malloc(bufferLength);
    write16BE(buffer, CMD_SESSION_OPEN);
    write32BE(buffer + 2, 1);     // 1 execution slot
    write32BE(buffer + 2 + 4, 0); // timeout
    recvLen = platform_exchange(context, buffer, bufferLength, responseBuffer,
                                sizeof(responseBuffer));
    free(buffer);
    if ((recvLen < 1) || (responseBuffer[0] != STATUS_CODE_EXEC_OK)) {
        fprintf(stderr, "OpenSession returned error 0x%x\n", responseBuffer[0]);
        goto error;
    }

    if (argc != 1) {
        result = process(context, argc, argv);
    } else {
        char data[4096];
        char *args[20];
        for (;;) {
            int argsCount = 1;
            bool platform_handled;
            printf(">");
            if ((fgets(data, sizeof(data), stdin) == NULL) ||
                (strlen(data) < 2)) {
                break;
            }
            data[strlen(data) - 1] = '\0';

            if (strcasecmp(data, "help") == 0) {
                usage(argv[0]);
                continue;
            }
            args[0] = argv[0];
            args[1] = strtok(data, " ");
            argsCount++;
            while ((args[argsCount] = strtok(NULL, " ")) != NULL) {
                argsCount++;
            }
            result =
                platform_process(context, argsCount, args, &platform_handled);
            if (!platform_handled) {
                result = process(context, argsCount, args);
            }
            if (result != 0) {
                break;
            }
        }
    }

    result = 0;

error:
    if (context != NULL) {
        platform_uninit(context);
    }

    return result;
}
