#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4267)  // disable size_t to uint32_t conversion warning
#pragma warning(disable: 4005)  // disable macro redefinition warning

#ifndef UNICODE
#define UNICODE
#endif

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

void chacha20_encrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
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

void find_key_and_nonce(const char* filename, uint8_t* key, uint8_t* nonce) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return;
    }

    // Pattern to search for
    uint8_t pattern[] = {
        0x32, 0x1D, 0x30, 0xF9, 0x48, 0x77, 0x82, 0x5A,
        0x3C, 0xBF, 0x73, 0x7F, 0xDD, 0x4F, 0x15, 0x75
    };

    uint8_t buffer[16];
    bool found = false;

    while (fread(buffer, 1, 16, file) == 16) {
        if (memcmp(buffer, pattern, 16) == 0) {
            // Found the pattern, read next 32 bytes as key
            if (fread(key, 1, 32, file) == 32) {
                found = true;

                // Initialize nonce with zeros
                memset(nonce, 0, 12);

                // Read 8 bytes for nonce and place them after the zero padding
                uint8_t temp_nonce[8];
                if (fread(temp_nonce, 1, 8, file) == 8) {
                    // Copy the 8 bytes to the end of the nonce (after 4 zero bytes)
                    memcpy(nonce + 4, temp_nonce, 8);
                }
            }
            break;
        }
        fseek(file, -15, SEEK_CUR);
    }

    fclose(file);
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

    return 0;
}

void read_target_location(const uint8_t* data, size_t file_size, uint32_t value, const std::vector<SectionInfo>& sections, uint32_t image_base) {
    printf("\nReading at RVA: 0x%08X\n", value);

    uint32_t file_offset = rva_to_file_offset(value, sections, image_base);
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

void analyze_encrypted_chunks(const uint8_t* data, size_t offset, const SectionInfo* section, const uint8_t* key, const uint8_t* nonce) {
    // Skip 0x29 bytes after pattern
    size_t target_offset = offset + 0x29;

    // Grab 9 chunks of 0x81 bytes each
    for (int chunk = 0; chunk < 9; chunk++) {
        size_t chunk_offset = target_offset + (chunk * 0x81);
        uint8_t chunk_data[0x81];
        memcpy(chunk_data, data + chunk_offset, 0x81);

        printf("\nDomain %d (offset 0x%zx):\n", chunk + 1, chunk_offset);
        printf("First 20 bytes: ");
        for (size_t i = 0; i < 20; i++) {
            printf("%02X ", chunk_data[i]);
        }
        printf("\n");

        printf("Full chunk (%d/9):\n", chunk + 1);
        for (size_t i = 0; i < 0x81; i++) {
            if (i % 16 == 0) printf("\n");
            printf("%02X ", chunk_data[i]);
        }
        printf("\n");
    }
    printf("\n----------------------------------------\n");
}

void analyze_pattern_location(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file\n");
        return;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(dos_header), 1, file);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        fclose(file);
        return;
    }

    // Get to PE header
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    // Read NT signature
    DWORD signature;
    fread(&signature, sizeof(DWORD), 1, file);
    if (signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        fclose(file);
        return;
    }

    // Read File header
    IMAGE_FILE_HEADER file_header;
    fread(&file_header, sizeof(file_header), 1, file);

    // Read Optional header
    IMAGE_OPTIONAL_HEADER32 optional_header;
    fread(&optional_header, sizeof(optional_header), 1, file);

    // Read section headers and build section info
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
    }

    // Get file size and read entire file
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

    // Pattern to search for: 01020304...32 in ASCII
    uint8_t pattern[] = {
        0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34,
        0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38,
        0x30, 0x39, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32,
        0x31, 0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36,
        0x31, 0x37, 0x31, 0x38, 0x31, 0x39, 0x32, 0x30,
        0x32, 0x31, 0x32, 0x32, 0x32, 0x33, 0x32, 0x34,
        0x32
    };
    const size_t pattern_size = sizeof(pattern);

    // Find pattern in file
    for (size_t i = 0; i < file_size - pattern_size; i++) {
        if (memcmp(data + i, pattern, pattern_size) == 0) {

            // Find which section contains our pattern
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
                printf("Pattern not found in any section\n");
                continue;
            }

            // Go back to find the start of the array
            size_t array_start = i - 36;  // Go back 9 DWORDs

            // Show disassembly around pattern
            analyze_encrypted_chunks(data, array_start, current_section, nullptr, nullptr);

            break;
        }
    }

    free(data);
}

void decrypt(const uint8_t* data, size_t file_size, const uint8_t* key, const uint8_t* nonce, const std::vector<SectionInfo>& sections, uint32_t image_base) {
    std::vector<std::string> c2_servers;
    uint8_t pattern[] = { 0x74, 0x72, 0x75, 0x65, 0x00, 0x66, 0x61, 0x6C, 0x73, 0x65 };
    const size_t pattern_size = sizeof(pattern);

    for (size_t i = 0; i < file_size - (pattern_size + 0x29 + 0x81 * 9); i++) {
        if (memcmp(data + i, pattern, pattern_size) == 0) {
            size_t target_offset = i + pattern_size + 0x29;

            for (int chunk = 8; chunk >= 0; chunk--) {
                size_t chunk_offset = target_offset + (chunk * 0x81);
                uint8_t chunk_data[0x81];
                memcpy(chunk_data, data + chunk_offset, 0x81);

                uint32_t counter = (8 - chunk) * 2;

                uint8_t plaintext[0x81] = { 0 };
                chacha20_encrypt(plaintext, chunk_data, 0x81, key, nonce, counter);

                if (plaintext[0] != 0) {
                    c2_servers.insert(c2_servers.begin(), std::string((char*)plaintext));
                }
            }
            break;
        }
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    printf("\n{\n");
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

// Add this before main() or at the start of main()
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
    if (!file) return;

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
    // Display ASCII art at the start
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

    printf("WARNING: This tool analyzes potentially malicious files. Make sure you change the extensions for the executables to .bin!\n\n");

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // Reset to default white color

    printf("Please drag and drop the Lumma binary onto this window\n");

    printf("Or use: LummaExtractor.exe <path_to_binary>\n");
    printf("Enter/drop path or press Enter to exit: ");

    char filepath[MAX_PATH];
    char input[MAX_PATH];

    if (argc != 2) {
        if (fgets(input, sizeof(input), stdin)) {
            // Remove newline if present
            input[strcspn(input, "\n")] = 0;

            // If user just pressed enter or input is empty, exit
            if (strlen(input) == 0 || input[0] == '\n' || input[0] == '\r') {
                printf("Exiting...\n");
                return -1;
            }

            // Check for shell execution attempts
            if (strchr(input, '&') || strchr(input, '|') || strchr(input, '>') ||
                strchr(input, '<') || strchr(input, ';') || strstr(input, "..")) {
                printf("Error: Invalid characters in path\n");
                printf("Press Enter to exit...");
                fgets(input, sizeof(input), stdin);
                return -1;
            }

            // Check for executable extensions
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

    find_key_and_nonce(filepath, key, nonce);

    // Extract and print build/user ID first
    extract_build_id(filepath);

    // Then process sections and decrypt
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        printf("Failed to open file\n");
        printf("Error: %s\n", strerror(errno));
        printf("Press Enter to exit...");
        fgets(input, sizeof(input), stdin);
        return -1;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(dos_header), 1, file);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        fclose(file);
        return -1;
    }

    // Get to PE header
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    // Read NT signature
    DWORD signature;
    fread(&signature, sizeof(DWORD), 1, file);
    if (signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        fclose(file);
        return -1;
    }

    // Read File header
    IMAGE_FILE_HEADER file_header;
    fread(&file_header, sizeof(file_header), 1, file);

    // Read Optional header
    IMAGE_OPTIONAL_HEADER32 optional_header;
    fread(&optional_header, sizeof(optional_header), 1, file);

    // Read section headers and build section info
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
    }

    // Get file size and read entire file
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

    // Process the encrypted data
    decrypt(data, file_size, key, nonce, sections, optional_header.ImageBase);
    free(data);

    printf("\nWould you like to decrypt another sample? (y/n): ");
    char choice;
    choice = getchar();
    while (getchar() != '\n'); // Clear input buffer

    if (choice == 'y' || choice == 'Y') {
        printf("\n");
        main(argc, argv); // Restart the program
    }
    else {
        printf("Press Enter to exit...");
        getchar();
    }

    return 0;
}
