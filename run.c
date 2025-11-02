#define _CRT_SECURE_NO_WARNINGS

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#pragma comment(lib, "bcrypt.lib")
#define U64_FORMAT "%llu"
#else
#include <fcntl.h>  
#include <unistd.h> 
#define U64_FORMAT "%lu"
#endif

#include <stdio.h>
#include <string.h> 
#include <stdlib.h>
#include <ctype.h>
#include "run.h" 

#define MAX_KEY_HEX 65
#define MAX_NONCE_HEX 17
#define MAX_STREAM_HEX_BUFFER 200

void salsa20_crypt(uint8_t key[32], int key_len, uint8_t nonce[8],
    uint64_t initial_counter, uint8_t* buffer, size_t length)
{
    uint32_t input[16];
    uint32_t keystream_words[16];
    uint8_t keystream_bytes[64];
    uint64_t block_counter = initial_counter;
    size_t i;

    const uint8_t constants[17] = "expand 32-byte k";
    const uint8_t constants_16[17] = "expand 16-byte k";

    if (key_len == 32) {
        input[0] = U8TO32_LITTLE(constants + 0);
        input[1] = U8TO32_LITTLE(key + 0);
        input[2] = U8TO32_LITTLE(key + 4);
        input[3] = U8TO32_LITTLE(key + 8);
        input[4] = U8TO32_LITTLE(key + 12);
        input[5] = U8TO32_LITTLE(constants + 4);
        input[10] = U8TO32_LITTLE(constants + 8);
        input[11] = U8TO32_LITTLE(key + 16);
        input[12] = U8TO32_LITTLE(key + 20);
        input[13] = U8TO32_LITTLE(key + 24);
        input[14] = U8TO32_LITTLE(key + 28);
        input[15] = U8TO32_LITTLE(constants + 12);
    }
    else { // key_len = 16
        input[0] = U8TO32_LITTLE(constants_16 + 0);
        input[1] = U8TO32_LITTLE(key + 0);
        input[2] = U8TO32_LITTLE(key + 4);
        input[3] = U8TO32_LITTLE(key + 8);
        input[4] = U8TO32_LITTLE(key + 12);
        input[5] = U8TO32_LITTLE(constants_16 + 4);
        input[10] = U8TO32_LITTLE(constants_16 + 8);
        input[11] = U8TO32_LITTLE(key + 0);
        input[12] = U8TO32_LITTLE(key + 4);
        input[13] = U8TO32_LITTLE(key + 8);
        input[14] = U8TO32_LITTLE(key + 12);
        input[15] = U8TO32_LITTLE(constants_16 + 12);
    }
    input[6] = U8TO32_LITTLE(nonce + 0);
    input[7] = U8TO32_LITTLE(nonce + 4);

    for (size_t offset = 0; offset < length; offset += 64) {

        //Cập nhật Block counter
        input[8] = (uint32_t)(block_counter & 0xffffffff);
        input[9] = (uint32_t)(block_counter >> 32);

        //Tạo khối keystream 64 byte MỚI
        salsa20_block(keystream_words, input);
        for (i = 0; i < 16; ++i) {
            U32TO8_LITTLE(keystream_bytes + i * 4, keystream_words[i]);
        }

        size_t bytes_to_xor = 64;
        if (offset + 64 > length) {
            bytes_to_xor = length - offset;
        }

        //Mã hóa/Giải mã
        for (i = 0; i < bytes_to_xor; ++i) {
            buffer[offset + i] ^= keystream_bytes[i];
        }
        block_counter++;
    }
}

void run_user(void) {
    uint8_t key[32] = { 0 };
    uint8_t nonce[8] = { 0 };
    int key_len = 0;

    uint8_t buffer[MAX_PLAINTEXT_BUFFER] = { 0 };
    size_t data_len = 0;

    const uint64_t num_blocks_to_generate = 1954; // 1.000.384 bits
    const char* filename = "data.txt";
    FILE* fp = NULL;
    printf("\nChon do dai khoa (16 hoac 32 byte): ");
    if (scanf("%d", &key_len) != 1) {
        printf("Nhap khong hop le.\n"); clean_stdin(); return;
    }
    clean_stdin();

    if (key_len != 16 && key_len != 32) {
        printf("Do dai khoa khong hop le.\n"); return;
    }

#ifdef _WIN32
    NTSTATUS status;
    status = BCryptGenRandom(NULL, key, key_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        printf("Khong the tao key ngau nhien!\n");
        return;
    }
    status = BCryptGenRandom(NULL, nonce, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        printf("Khong the tao nonce ngau nhien!\n");
        return;
    }
    printf("Da tao key/nonce ngau nhien\n");
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Khong the mo /dev/urandom");
        return;
    }
    if (read(fd, key, key_len) != (ssize_t)key_len) {
        printf("Khong doc du %d byte cho key.\n", key_len);
        close(fd); return;
    }
    if (read(fd, nonce, 8) != 8) {
        printf("Khong doc du 8 byte cho nonce.\n");
        close(fd); return;
    }
    close(fd);
    printf("Da tao key/nonce ngau nhien\n");
#endif
    printf("Nhap plaintext (toi da %d byte):\n", MAX_PLAINTEXT_BUFFER - 1);
    if (fgets((char*)buffer, MAX_PLAINTEXT_BUFFER, stdin) == NULL) {
        buffer[0] = '\0';
    }
    buffer[strcspn((char*)buffer, "\n")] = 0;
    data_len = strlen((const char*)buffer);
    printf("\nKhoa (%d byte - Dang Hex): \n", key_len);
    for (int i = 0; i < key_len; i++) printf("%02x", key[i]);
    printf("\nNonce (8 byte - Dang Hex): \n");
    for (int i = 0; i < 8; i++) printf("%02x", nonce[i]);
    printf("\nBo dem khoi bat dau: 0\n"); // Mặc định là 0
    printf("Plaintext (%zu byte): %s\n", data_len, buffer);
    printf("\nDang ma hoa...\n");
    salsa20_crypt(key, key_len, nonce, 0, buffer, data_len);
    printf("Ciphertext (%zu byte - Dang Hex):\n", data_len);
    for (size_t j = 0; j < data_len; ++j) {
        printf("%02x ", buffer[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }
    if (data_len % 16 != 0) printf("\n");
    salsa20_crypt(key, key_len, nonce, 0, buffer, data_len);
    printf("Plaintext sau giai ma: %s\n", buffer);

    fp = fopen(filename, "w");
    if (fp == NULL) {
        printf("Khong the mo file %s de ghi.\n", filename);
        return;
    }
    uint32_t input[16];
    const uint8_t constants[17] = "expand 32-byte k";
    const uint8_t constants_16[17] = "expand 16-byte k";

    if (key_len == 32) {
        input[0] = U8TO32_LITTLE(constants + 0); input[1] = U8TO32_LITTLE(key + 0); input[2] = U8TO32_LITTLE(key + 4); input[3] = U8TO32_LITTLE(key + 8); input[4] = U8TO32_LITTLE(key + 12); input[5] = U8TO32_LITTLE(constants + 4); input[10] = U8TO32_LITTLE(constants + 8); input[11] = U8TO32_LITTLE(key + 16); input[12] = U8TO32_LITTLE(key + 20); input[13] = U8TO32_LITTLE(key + 24); input[14] = U8TO32_LITTLE(key + 28); input[15] = U8TO32_LITTLE(constants + 12);
    }
    else { // key_len = 16
        input[0] = U8TO32_LITTLE(constants_16 + 0); input[1] = U8TO32_LITTLE(key + 0); input[2] = U8TO32_LITTLE(key + 4); input[3] = U8TO32_LITTLE(key + 8); input[4] = U8TO32_LITTLE(key + 12); input[5] = U8TO32_LITTLE(constants_16 + 4); input[10] = U8TO32_LITTLE(constants_16 + 8); input[11] = U8TO32_LITTLE(key + 0); input[12] = U8TO32_LITTLE(key + 4); input[13] = U8TO32_LITTLE(key + 8); input[14] = U8TO32_LITTLE(key + 12); input[15] = U8TO32_LITTLE(constants_16 + 12);
    }
    input[6] = U8TO32_LITTLE(nonce + 0);
    input[7] = U8TO32_LITTLE(nonce + 4);

    uint32_t keystream_words[16];
    uint8_t keystream_bytes[64];
    size_t i;

    // Vòng lặp để ghi file
    for (uint64_t block_counter = 0; block_counter < num_blocks_to_generate; ++block_counter) {
        input[8] = (uint32_t)(block_counter & 0xffffffff);
        input[9] = (uint32_t)(block_counter >> 32);

        salsa20_block(keystream_words, input);

        for (i = 0; i < 16; ++i) {
            U32TO8_LITTLE(keystream_bytes + (i * 4), keystream_words[i]);
        }
        for (i = 0; i < 64; ++i) {
            uint8_t byte = keystream_bytes[i];
            for (int j = 7; j >= 0; j--) {
                fprintf(fp, "%d", (byte >> j) & 1);
            }
        }
    }
    fclose(fp);

    printf("\nDa tao " U64_FORMAT " khoi (" U64_FORMAT " bits) vao file %s\n",
        num_blocks_to_generate, num_blocks_to_generate * 512, filename);
}

void run_test_vectors(void) {
    uint8_t key[32] = { 0 };
    uint8_t nonce[8] = { 0 };
    uint64_t block_counter = 0;
    int key_len = 0;
    uint8_t expected_keystream[64];
    bool key_found = false, nonce_found = false, stream_found = false;
    int vector_count = 0;
    int success_count = 0;

    char filename[100] = { 0 };
    printf("Nhap ten file test vector (vi du: test_vector256.txt): ");
    if (scanf("%99s", filename) != 1) {
        printf("Loi doc ten file.\n"); clean_stdin(); return;
    }
    clean_stdin();

    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Khong the mo file %s\n", filename);
        return;
    }

    char line[256];
    char hex_buffer[MAX_STREAM_HEX_BUFFER] = { 0 };

    printf("Dang doc file %s\n", filename);

    while (fgets(line, sizeof(line), fp) != NULL) {
        char* start = line;
        while (isspace((unsigned char)*start)) start++;
        char* end = start + strlen(start) - 1;
        while (end > start && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';

        if (strlen(start) == 0 || start[0] == '[' || strncmp(start, "Set", 3) == 0 || strncmp(start, "Test vectors", 12) == 0 || start[0] == '=') {
            continue;
        }

        if (strncmp(start, "key = ", 6) == 0) {
            memset(hex_buffer, 0, sizeof(hex_buffer));
            strncat(hex_buffer, start + 6, sizeof(hex_buffer) - strlen(hex_buffer) - 1);

            long current_pos = ftell(fp);
            while (fgets(line, sizeof(line), fp) != NULL) {
                char* next_start = line;
                while (isspace((unsigned char)*next_start)) next_start++;
                if (strlen(next_start) > 0 && strncmp(next_start, "IV = ", 5) != 0 && strncmp(next_start, "stream[", 7) != 0 && strncmp(next_start, "xor-digest", 10) != 0 && strncmp(next_start, "Set", 3) != 0 && next_start[0] != '[' && next_start[0] != '=') {
                    char* next_end = next_start + strlen(next_start) - 1;
                    while (next_end > next_start && isspace((unsigned char)*next_end)) next_end--;
                    *(next_end + 1) = '\0';
                    if (strlen(hex_buffer) + strlen(next_start) < sizeof(hex_buffer)) {
                        strncat(hex_buffer, next_start, sizeof(hex_buffer) - strlen(hex_buffer) - 1);
                        current_pos = ftell(fp);
                    }
                    else {
                        printf("Buffer khong du cho cho key hex.\n"); fclose(fp); return;
                    }
                }
                else {
                    fseek(fp, current_pos, SEEK_SET);
                    break;
                }
            }
            key_len = (int)strlen(hex_buffer) / 2;
            if (key_len != 16 && key_len != 32) {
                printf("Key hex '%s' co do dai khong hop le (%d byte).\n", hex_buffer, key_len); fclose(fp); return;
            }
            if (hex_string_to_bytes(key, hex_buffer, (size_t)key_len) != 0) { fclose(fp); return; }
            key_found = true;
            nonce_found = false;
            stream_found = false;
            printf("\nDa tim thay key (%d byte).\n", key_len);
        }
        else if (strncmp(start, "IV = ", 5) == 0 && key_found) {
            memset(hex_buffer, 0, sizeof(hex_buffer));
            strncpy(hex_buffer, start + 5, sizeof(hex_buffer) - 1);
            if (strlen(hex_buffer) != 16) {
                printf("IV hex '%s' phai co 16 ky tu.\n", hex_buffer); fclose(fp); return;
            }
            if (hex_string_to_bytes(nonce, hex_buffer, 8) != 0) { fclose(fp); return; }
            nonce_found = true;
            printf("Da tim thay IV/Nonce.\n");
        }
        else if (strncmp(start, "stream[0..63] = ", 16) == 0 && key_found && nonce_found) {
            block_counter = 0;
            memset(hex_buffer, 0, sizeof(hex_buffer));
            strncat(hex_buffer, start + 16, sizeof(hex_buffer) - strlen(hex_buffer) - 1);

            long current_pos = ftell(fp);
            while (fgets(line, sizeof(line), fp) != NULL) {
                char* next_start = line;
                while (isspace((unsigned char)*next_start)) next_start++;
                if (strlen(next_start) > 0 && strncmp(next_start, "key = ", 6) != 0 && strncmp(next_start, "IV = ", 5) != 0 && strncmp(next_start, "stream[", 7) != 0 && strncmp(next_start, "xor-digest", 10) != 0 && strncmp(next_start, "Set", 3) != 0 && next_start[0] != '[' && next_start[0] != '=') {
                    char* next_end = next_start + strlen(next_start) - 1;
                    while (next_end > next_start && isspace((unsigned char)*next_end)) next_end--;
                    *(next_end + 1) = '\0';
                    if (strlen(hex_buffer) + strlen(next_start) < sizeof(hex_buffer)) {
                        strncat(hex_buffer, next_start, sizeof(hex_buffer) - strlen(hex_buffer) - 1);
                        current_pos = ftell(fp);
                    }
                    else {
                        printf("Buffer khong du cho cho stream hex.\n"); fclose(fp); return;
                    }
                }
                else {
                    fseek(fp, current_pos, SEEK_SET);
                    break;
                }
            }

            if (strlen(hex_buffer) != 128) {
                printf("Stream[0..63] hex '%s' phai co 128 ky tu, tim thay %zu.\n", hex_buffer, strlen(hex_buffer)); fclose(fp); return;
            }
            if (hex_string_to_bytes(expected_keystream, hex_buffer, 64) != 0) { fclose(fp); return; }
            stream_found = true;
            printf("Da tim thay stream[0..63].\n");
        }

        if (key_found && nonce_found && stream_found) {
            vector_count++;
            printf("\nKiem tra VECTOR #%d\n", vector_count);

            uint32_t input[16];
            uint32_t generated_keystream_words[16];
            uint8_t generated_keystream_bytes[64];
            const uint8_t constants[17] = "expand 32-byte k";
            const uint8_t constants_16[17] = "expand 16-byte k";
            size_t i;

            if (key_len == 32) {
                input[0] = U8TO32_LITTLE(constants + 0); input[1] = U8TO32_LITTLE(key + 0); input[2] = U8TO32_LITTLE(key + 4); input[3] = U8TO32_LITTLE(key + 8); input[4] = U8TO32_LITTLE(key + 12); input[5] = U8TO32_LITTLE(constants + 4); input[10] = U8TO32_LITTLE(constants + 8); input[11] = U8TO32_LITTLE(key + 16); input[12] = U8TO32_LITTLE(key + 20); input[13] = U8TO32_LITTLE(key + 24); input[14] = U8TO32_LITTLE(key + 28); input[15] = U8TO32_LITTLE(constants + 12);
            }
            else { // key_len = 16
                input[0] = U8TO32_LITTLE(constants_16 + 0); input[1] = U8TO32_LITTLE(key + 0); input[2] = U8TO32_LITTLE(key + 4); input[3] = U8TO32_LITTLE(key + 8); input[4] = U8TO32_LITTLE(key + 12); input[5] = U8TO32_LITTLE(constants_16 + 4); input[10] = U8TO32_LITTLE(constants_16 + 8); input[11] = U8TO32_LITTLE(key + 0); input[12] = U8TO32_LITTLE(key + 4); input[13] = U8TO32_LITTLE(key + 8); input[14] = U8TO32_LITTLE(key + 12); input[15] = U8TO32_LITTLE(constants_16 + 12);
            }
            input[6] = U8TO32_LITTLE(nonce + 0); input[7] = U8TO32_LITTLE(nonce + 4);
            input[8] = (uint32_t)(block_counter & 0xffffffff); input[9] = (uint32_t)(block_counter >> 32);

            salsa20_block(generated_keystream_words, input);
            for (i = 0; i < 16; ++i) {
                U32TO8_LITTLE(generated_keystream_bytes + i * 4, generated_keystream_words[i]);
            }

            printf("Khoa (%d byte - Dang Hex): \n", key_len);
            for (i = 0; i < (size_t)key_len; i++) printf("%02x", key[i]);
            printf("\nNonce (IV) (8 byte - Dang Hex): \n");
            for (i = 0; i < 8; i++) printf("%02x", nonce[i]);
            printf("\nBo dem khoi (tu stream[0..63]): " U64_FORMAT "\n", block_counter);

            printf("\n--- Keystream[0..63] KY VONG (tu file) ---\n");
            for (i = 0; i < 64; ++i) {
                printf("%02x ", expected_keystream[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n--- Keystream[0..63] DA TAO (tinh toan) ---\n");
            for (i = 0; i < 64; ++i) {
                printf("%02x ", generated_keystream_bytes[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            if (memcmp(expected_keystream, generated_keystream_bytes, 64) == 0) {
                printf("\nKeystream tinh toan khop voi file.\n");
                success_count++;
            }
            else {
                printf("\nKeystream tinh toan khong khop voi file.\n");
            }

            key_found = false;
            nonce_found = false;
            stream_found = false;
        }
    }
    fclose(fp);
    if (vector_count == 0) {
        printf("\nKhong tim thay bat ky test vector nao (key, IV, stream[0..63]) trong file.\n");
    }
    else {
        printf("\nDa kiem tra %d test vector. (Thanh cong: %d, That bai: %d)\n",
            vector_count, success_count, vector_count - success_count);
    }
}
