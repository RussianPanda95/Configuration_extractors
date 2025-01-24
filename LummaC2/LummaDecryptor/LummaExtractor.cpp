#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4267)

#ifndef UNICODE
#define UNICODE
#endif

#include <stdio.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cstdlib>
#include <windows.h>
#include <vector>
#include <iostream>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

void chacha20_block(uint32_t output[16], const uint32_t input[16]) {
    uint32_t x[16];
    memcpy(x, input, 64);

    for (int i = 0; i < 10; i++) {
        QUARTERROUND(x[0], x[4], x[8], x[12])
            QUARTERROUND(x[1], x[5], x[9], x[13])
            QUARTERROUND(x[2], x[6], x[10], x[14])
            QUARTERROUND(x[3], x[7], x[11], x[15])

            QUARTERROUND(x[0], x[5], x[10], x[15])
            QUARTERROUND(x[1], x[6], x[11], x[12])
            QUARTERROUND(x[2], x[7], x[8], x[13])
            QUARTERROUND(x[3], x[4], x[9], x[14])
    }

    for (int i = 0; i < 16; i++) {
        output[i] = x[i] + input[i];
    }
}

void chacha20(uint8_t* output, const uint8_t* input, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16];

    const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    memcpy(state, constants, 16);

    memcpy(state + 4, key, 32);

    state[12] = counter;
    memcpy(state + 13, nonce, 12);

    uint32_t block[16];
    uint8_t keystream[64];

    for (size_t i = 0; i < len; i += 64) {
        chacha20_block(block, state);

        for (int j = 0; j < 16; j++) {
            keystream[4 * j + 0] = block[j] & 0xff;
            keystream[4 * j + 1] = (block[j] >> 8) & 0xff;
            keystream[4 * j + 2] = (block[j] >> 16) & 0xff;
            keystream[4 * j + 3] = (block[j] >> 24) & 0xff;
        }

        size_t chunk_size = ((len - i) < 64) ? (len - i) : 64;
        for (size_t j = 0; j < chunk_size; j++) {
            output[i + j] = input[i + j] ^ keystream[j];
        }

        state[12]++;
    }
}

bool get_key_and_nonce(const char* filename, uint8_t* key, uint8_t* nonce) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", filename);
        return false;
    }

    uint8_t pattern[] = {
        0x32, 0x1D, 0x30, 0xF9, 0x48, 0x77, 0x82, 0x5A,
        0x3C, 0xBF, 0x73, 0x7F, 0xDD, 0x4F, 0x15, 0x75
    };

    uint8_t buffer[16];
    bool found = false;

    while (fread(buffer, 1, 16, file) == 16) {
        if (memcmp(buffer, pattern, 16) == 0) {
            if (fread(key, 1, 32, file) == 32) {
                found = true;

                for (int i = 0; i < 32; i++) {
                }


                memset(nonce, 0, 12);

                uint8_t temp_nonce[8];
                if (fread(temp_nonce, 1, 8, file) == 8) {
                    memcpy(nonce + 4, temp_nonce, 8);
                }
            }
            break;
        }
        fseek(file, -15, SEEK_CUR);
    }

    fclose(file);
    return found;
}

struct SectionInfo {
    uint32_t virtual_address;
    uint32_t raw_address;
    uint32_t raw_size;
    uint32_t virtual_size;
};

uint32_t rva_to_file_offset(uint32_t rva, const std::vector<SectionInfo>& sections, uint32_t image_base) {
    uint32_t adjusted_rva = rva - image_base;

    for (const auto& section : sections) {
        uint32_t section_start = section.virtual_address;
        uint32_t section_end = section.virtual_address + section.virtual_size;

        if (adjusted_rva >= section_start && adjusted_rva < section_end) {
            uint32_t offset_in_section = adjusted_rva - section_start;
            uint32_t file_offset = section.raw_address + offset_in_section;
            return file_offset;
        }
    }

    printf("RVA not found in any section\n");
    return 0;
}

void read_target_location(const uint8_t* data, size_t file_size, uint32_t value, const std::vector<SectionInfo>& sections) {
    printf("\nReading at RVA: 0x%08X\n", value);

    uint32_t file_offset = rva_to_file_offset(value, sections, 0x400000);
    if (file_offset == 0) {
        printf("Error: Could not map RVA to file offset\n");
        return;
    }

    printf("Mapped to file offset: 0x%08X\n", file_offset);
    printf("----------------------------------------\n");

    if (file_offset + 20 > file_size) {
        printf("Error: Offset beyond file size (file size: 0x%zx)\n", file_size);
        return;
    }

    printf("First 20 bytes: ");
    for (size_t i = 0; i < 20; i++) {
        printf("%02X ", data[file_offset + i]);
    }
    printf("\n");
}

void dism_pattern(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file\n");
        return;
    }

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(dos_header), 1, file);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        fclose(file);
        return;
    }

    fseek(file, dos_header.e_lfanew, SEEK_SET);

    DWORD signature;
    fread(&signature, sizeof(DWORD), 1, file);
    if (signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        fclose(file);
        return;
    }

    IMAGE_FILE_HEADER file_header;
    fread(&file_header, sizeof(file_header), 1, file);

    IMAGE_OPTIONAL_HEADER32 optional_header;
    fread(&optional_header, sizeof(optional_header), 1, file);

    std::vector<SectionInfo> sections;
    printf("\nReading sections:\n");
    for (int i = 0; i < file_header.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER section_header;
        fread(&section_header, sizeof(section_header), 1, file);

        SectionInfo info;
        info.virtual_address = section_header.VirtualAddress;
        info.raw_address = section_header.PointerToRawData;
        info.raw_size = section_header.SizeOfRawData;
        info.virtual_size = section_header.Misc.VirtualSize;
        sections.push_back(info);

        char name[9] = { 0 };
        memcpy(name, section_header.Name, 8);
    }

    printf("\nSection Information:\n");
    for (const auto& section : sections) {
        printf("VA: 0x%08X - 0x%08X, Raw: 0x%08X - 0x%08X\n",
            section.virtual_address,
            section.virtual_address + section.virtual_size,
            section.raw_address,
            section.raw_address + section.raw_size);
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* data = (uint8_t*)malloc(file_size);
    if (!data) {
        printf("Memory allocation failed\n");
        fclose(file);
        return;
    }
    fread(data, 1, file_size, file);
    fclose(file);

    uint8_t pattern[] = { 0x75, 0x86, 0x44, 0x00 };
    const size_t pattern_size = sizeof(pattern);

    for (size_t i = 0; i < file_size - pattern_size; i++) {
        if (memcmp(data + i, pattern, pattern_size) == 0) {

            uint32_t pattern_rva = 0;
            const SectionInfo* current_section = nullptr;

            for (const auto& section : sections) {
                if (i >= section.raw_address && i < section.raw_address + section.raw_size) {
                    pattern_rva = section.virtual_address + (i - section.raw_address);
                    current_section = &section;
                    break;
                }
            }

            if (!current_section) {
                continue;
            }

            size_t start = i - (8 * 4);

            for (size_t j = start; j <= i; j += 4) {
                uint32_t current_rva = current_section->virtual_address +
                    (j - current_section->raw_address);

                uint32_t value = *(uint32_t*)(data + j);


                if ((value & 0xFF000000) == 0) {
                    read_target_location(data, file_size, value, sections);
                }
            }
            break;
        }
    }

    free(data);
}

void decrypt(const uint8_t* data, size_t file_size, const uint8_t* key, const uint8_t* nonce, const std::vector<SectionInfo>& sections) {
    std::vector<std::string> c2_servers;

    uint8_t pattern[] = { 0x75, 0x86, 0x44, 0x00, 0x30 };
    const size_t pattern_size = sizeof(pattern);

    for (size_t i = 0; i < file_size - pattern_size; i++) {
        if (data[i] == 0x75 &&
            data[i + 2] == 0x44 &&
            data[i + 3] == 0x00 &&
            data[i + 4] == 0x30) {

            size_t start = i - (8 * 4);
            uint32_t counter = 0;

            for (size_t j = start; j <= i; j += 4) {
                uint32_t value = *(uint32_t*)(data + j);
                if ((value & 0xFF000000) == 0) {
                    uint32_t file_offset = rva_to_file_offset(value, sections, 0x400000);
                    if (file_offset && file_offset + 32 <= file_size) {
                        const uint8_t* ciphertext = data + file_offset;
                        uint8_t plaintext[32] = { 0 };

                        chacha20(plaintext, ciphertext, 32, key, nonce, counter);

                        if (plaintext[0] != 0) {
                            c2_servers.push_back(std::string((char*)plaintext));
                        }

                        counter += 2;
                    }
                }
            }
            break;
        }
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    printf("  \"c2_domains\": [\n");
    for (size_t i = 0; i < c2_servers.size(); i++) {
        printf("    \"%s\"%s\n",
            c2_servers[i].c_str(),
            (i < c2_servers.size() - 1) ? "," : "");
    }
    printf("  ]\n}\n");

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

bool is_executable_extension(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return false;

    const char* dangerous_exts[] = {
        ".exe", ".bat",".cmd", ".com", ".scr", ".pif", ".msi",
        ".vbs", ".js", ".wsf", ".wsh", ".ps1", ".msc", ".hta"
    };

    for (const char* dangerous : dangerous_exts) {
        if (_stricmp(ext, dangerous) == 0) return true;
    }
    return false;
}

const char* LUMMA_ASCII_ART = R"(
                      -.                                                                  
                     --:                                                                  
                    :---.                                                                 
                    -----                                                                 
                    ------.                                                               
                    :------.                                                              
                     -------:                                                             
                     .--------:                      .:::-:::.                            
                       ---------:.                .------------:                          
                   .-:. .----------:.            :-:..:-----------::....                  
                    .------------------:..              .:-----------::...                
                      .-----------------------------------------:.                        
                         ..:----------------------------------:                           
                       ::-----------------------------------:                             
                        :--------------------:::::---------:                              
                           .:--------:::..   :-------------                               
                                          .---------------                                
                                       .:----------------.                                
                                     .-------------------                                 
                                    --------------------                                  
                                  .-------------------:                                   
                                 -------------------:.                                    
                                --------:........                                         
                               --------:                                                  
                              :--------                                                   
                              --------:                                                   
                              --------                                                    
                              -------.                                                    
                              -------                                                     
                              .-----                                                      
                               .---:                                                      
                                :--                                                       
                                 ..                                                       

)";

void extract_build_id(const char* filename) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file for Build ID extraction\n");
        return;
    }

    uint8_t pattern[] = {
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10,
        0xF0, 0xE1, 0xD2, 0xC3
    };

    uint8_t buffer[12];
    bool found = false;

    while (fread(buffer, 1, sizeof(buffer), file) == sizeof(buffer)) {
        if (memcmp(buffer, pattern, sizeof(pattern)) == 0) {
            fseek(file, 4, SEEK_CUR);

            char full_id[256] = { 0 };
            int i = 0;
            char c;

            while (fread(&c, 1, 1, file) == 1 && c != '\0' && i < 255) {
                full_id[i++] = c;
            }

            char* separator = strstr(full_id, "--");
            if (separator) {
                *separator = '\0';
                SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                printf("\n{\n");
                printf("  \"build info\": {\n");
                printf("    \"user_id\": \"%s\",\n", full_id);
                if (strlen(separator + 2) > 0) {
                    printf("    \"build_id\": \"%s\"\n", separator + 2);
                }
                printf("  },\n");
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            else if (strlen(full_id) > 0) {

                printf("\nUser ID: %s\n", full_id);
            }

            found = true;
            break;
        }
        fseek(file, -11, SEEK_CUR);
    }

    if (!found) {
        printf("\nCannot determine User ID and Build ID\n");
    }

    fclose(file);
}

int main(int argc, char* argv[]) {
    printf("%s\n", LUMMA_ASCII_ART);
    printf(R"(
=====================================
   _     _   _ __  __ __  __    _      
  | |   | | | |  \/  |  \/  |  / \     
  | |   | | | | |\/| | |\/| | / _ \    
  | |___| |_| | |  | | |  | |/ ___ \   
  |_____|_____|_|  |_|_|  |_/_/   \_\  
  
  STEALER CONFIGURATION EXTRACTOR

  Author: RussianPanda
=====================================
)");

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

    printf("WARNING: This tool analyzes malicious files. Make sure you change the extensions for the executables to .bin!\n\n");

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    printf("Please drag and drop the Lumma binary onto this window\n");

    printf("Or use: LummaExtractor.exe <path_to_binary>\n");
    printf("Enter/drop path or press Enter to exit: ");

    char filepath[MAX_PATH];
    char input[MAX_PATH];

    if (argc != 2) {
        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = 0;

            if (strlen(input) == 0 || input[0] == '\n' || input[0] == '\r') {
                printf("Exiting...\n");
                return -1;
            }

            if (strchr(input, '&') || strchr(input, '|') || strchr(input, '>') ||
                strchr(input, '<') || strchr(input, ';') || strstr(input, "..")) {
                printf("Error: Invalid characters in path\n");
                printf("Press Enter to exit...");
                fgets(input, sizeof(input), stdin);
                return -1;
            }

            if (is_executable_extension(input)) {
                printf("Error: Cannot process executable files\n");
                printf("Press Enter to exit...");
                fgets(input, sizeof(input), stdin);
                return -1;
            }

            strncpy(filepath, input, MAX_PATH - 1);
            filepath[MAX_PATH - 1] = '\0';
        }
        else {
            return -1;
        }
    }
    else {
        if (strchr(argv[1], '&') || strchr(argv[1], '|') || strchr(argv[1], '>') ||
            strchr(argv[1], '<') || strchr(argv[1], ';') || strstr(argv[1], "..")) {
            printf("Error: Invalid characters in path\n");
            return -1;
        }

        if (is_executable_extension(argv[1])) {
            printf("Error: Cannot process executable files\n");
            return -1;
        }

        strncpy(filepath, argv[1], MAX_PATH - 1);
        filepath[MAX_PATH - 1] = '\0';
    }

    uint8_t key[32];
    uint8_t nonce[12];

    if (!get_key_and_nonce(filepath, key, nonce)) {
        printf("Failed to find key and nonce in binary\n");
        printf("Press Enter to exit...");
        fgets(input, sizeof(input), stdin);
        return -1;
    }

    extract_build_id(filepath);

    FILE* file = fopen(filepath, "rb");
    if (!file) {
        printf("Failed to open file\n");
        printf("Press Enter to exit...");
        fgets(input, sizeof(input), stdin);
        return -1;
    }

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(dos_header), 1, file);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        fclose(file);
        return -1;
    }

    fseek(file, dos_header.e_lfanew, SEEK_SET);

    DWORD signature;
    fread(&signature, sizeof(DWORD), 1, file);
    if (signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        fclose(file);
        return -1;
    }

    IMAGE_FILE_HEADER file_header;
    fread(&file_header, sizeof(file_header), 1, file);

    IMAGE_OPTIONAL_HEADER32 optional_header;
    fread(&optional_header, sizeof(optional_header), 1, file);

    std::vector<SectionInfo> sections;
    for (int i = 0; i < file_header.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER section_header;
        fread(&section_header, sizeof(section_header), 1, file);

        SectionInfo info;
        info.virtual_address = section_header.VirtualAddress;
        info.raw_address = section_header.PointerToRawData;
        info.raw_size = section_header.SizeOfRawData;
        info.virtual_size = section_header.Misc.VirtualSize;
        sections.push_back(info);

        char name[9] = { 0 };
        memcpy(name, section_header.Name, 8);
    }


    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* data = (uint8_t*)malloc(file_size);
    if (!data) {
        printf("Memory allocation failed\n");
        fclose(file);
        return -1;
    }
    fread(data, 1, file_size, file);
    fclose(file);

    decrypt(data, file_size, key, nonce, sections);
    free(data);

    printf("\Extraction complete. Press Enter to exit...");
    fgets(input, sizeof(input), stdin);

    return 0;
}
