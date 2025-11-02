#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
    #include <windows.h>  
    #include <bcrypt.h>   
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <fcntl.h>  // Cho O_RDONLY
    #include <unistd.h> // Cho open(), read(), close()
#endif
#include <stdio.h>
#include <string.h> 
#include <stdlib.h>
#include <ctype.h>
#include "run.h"

#define MAX_KEY_HEX 65  // 32*2 + 1
#define MAX_NONCE_HEX 17 // 8*2 + 1
#define MAX_PLAIN_HEX (MAX_SIZE * 2 + 1) // 64*2 + 1
#define MAX_STREAM_HEX_BUFFER 200

void perform_salsa20(uint8_t key[32], int key_len, uint8_t nonce[8],
    uint64_t block_counter, uint8_t* plaintext, size_t length)
{
    size_t i;
    const uint8_t constants[17] = "expand 32-byte k";
    const uint8_t constants_16[17] = "expand 16-byte k";
    uint32_t input[16];

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
    else { // key_len = 16 bytes
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
    input[8] = (uint32_t)(block_counter & 0xffffffff);
    input[9] = (uint32_t)(block_counter >> 32);

    uint32_t keystream_words[16];
    salsa20_block(keystream_words, input);

    uint8_t keystream_bytes[MAX_SIZE];
    for (i = 0; i < 16; ++i) {
        U32TO8_LITTLE(keystream_bytes + i * 4, keystream_words[i]);
    }

    uint8_t ciphertext[MAX_SIZE + 1] = { 0 };
    for (i = 0; i < length; ++i) {
        ciphertext[i] = plaintext[i] ^ keystream_bytes[i];
    }
    ciphertext[length] = '\0';

    uint8_t decrypted[MAX_SIZE + 1] = { 0 };
    for (i = 0; i < length; ++i) {
        decrypted[i] = ciphertext[i] ^ keystream_bytes[i];
    }
    decrypted[length] = '\0';

    printf("\nKhoa (%d byte - Dang Hex): \n", key_len);
    for (i = 0; i < (size_t)key_len; i++) printf("%02x", key[i]);
    printf("\nNonce (8 byte - Dang Hex): \n");
    for (i = 0; i < 8; i++) printf("%02x", nonce[i]);
    printf("\nBlock Counter: %lu\n", block_counter); 
    printf("Plaintext da nhap: %s\n", plaintext);
    printf("Plaintext (%zu byte - Dang Hex):\n", length);
    for (size_t j = 0; j < length; ++j) {
        printf("%02x ", plaintext[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }
    if (length % 16 != 0) printf("\n");

    printf("\nKeystream (64 byte - Dang Hex):\n");
    for (size_t j = 0; j < MAX_SIZE; ++j) {
        printf("%02x ", keystream_bytes[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }

    printf("\nCiphertext (%zu byte - Dang Hex):\n", length);
    for (size_t j = 0; j < length; ++j) {
        printf("%02x ", ciphertext[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }
    if (length % 16 != 0) printf("\n");

    printf("\nDa giai ma: %s\n", decrypted);

    if (memcmp(plaintext, decrypted, length) == 0) {
        printf("\nPlaintext khoi phuc dung.\n");
    }
    else {
        printf("\nPlaintext khoi phuc sai.\n");
    }
}

//Hàm cho phép nhập vào từ bàn phím
void run_user(void) {
    uint8_t key[32] = { 0 };
    uint8_t nonce[8] = { 0 };
    int key_len = 0;
    uint64_t user_block_counter = 0;
    uint8_t plaintext[MAX_SIZE + 1] = { 0 };
    size_t plaintext_len = 0;
    const uint64_t num_blocks_to_generate = 1954; // 1.000.384 bits
    const char* filename = "data.txt";
    FILE* fp = NULL;

    printf("Chon do dai khoa (16 hoac 32 byte): ");
    if (scanf("%d", &key_len) != 1) {
        printf("Nhap khong hop le.\n"); clean_stdin(); return;
    }
    clean_stdin();

    if (key_len != 16 && key_len != 32) {
        printf("Do dai khoa khong hop le.\n"); return;
    }
#ifdef _WIN32
    NTSTATUS status;
    //Tạo key ngẫu nhiên
    status = BCryptGenRandom(NULL, key, key_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        printf("Khong the tao key ngau nhien!\n");
        return;
    }
    printf("Da tao key ngau nhien (%d byte).\n", key_len);

    //Tạo nonce ngẫu nhiên
    status = BCryptGenRandom(NULL, nonce, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        printf("Khong the tao nonce ngau nhien!\n");
        return;
    }
    printf("Da tao nonce ngau nhien (8 byte).\n");
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Khong the mo /dev/urandom");
        return;
    }

    if (read(fd, key, key_len) != (ssize_t)key_len) {
        printf("Khong doc du %d byte cho key.\n", key_len);
        close(fd);
        return;
    }
    printf("Da tao key ngau nhien (%d byte).\n", key_len);

    if (read(fd, nonce, 8) != 8) {
        printf("Khong doc du 8 byte cho nonce.\n");
        close(fd);
        return;
    }
    printf("Da tao nonce ngau nhien (8 byte).\n");
    close(fd);

#endif
    printf("Nhap bo dem khoi cho viec ma hoa (vi du: 0): ");
    if (scanf("%lu", &user_block_counter) != 1) {
        printf("Loi doc bo dem khoi.\n"); clean_stdin(); return;
    }
    clean_stdin();

    printf("Nhap plaintext (toi da %d byte):\n", MAX_SIZE);
    if (fgets((char*)plaintext, MAX_SIZE + 1, stdin) == NULL) {
        plaintext[0] = '\0';
    }
    plaintext[strcspn((char*)plaintext, "\n")] = 0;
    plaintext_len = strlen((const char*)plaintext);
    perform_salsa20(key, key_len, nonce, user_block_counter, plaintext, plaintext_len);
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
    input[6] = U8TO32_LITTLE(nonce + 0); // Dùng nonce ngẫu nhiên
    input[7] = U8TO32_LITTLE(nonce + 4); // Dùng nonce ngẫu nhiên

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
}

void run_test_vectors(void) {
    uint8_t key[32] = { 0 };
    uint8_t nonce[8] = { 0 };
    uint64_t block_counter = 0;
    int key_len = 0;
    uint8_t expected_keystream[64] = { 0 };
    bool key_found = false, nonce_found = false, stream_found = false;
    int vector_count = 0;
    int success_count = 0; // Đếm số test thành công

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
                printf("Loi: IV hex '%s' phai co 16 ky tu.\n", hex_buffer); fclose(fp); return;
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
                printf("Loi: stream[0..63] hex '%s' phai co 128 ky tu, tim thay %zu.\n", hex_buffer, strlen(hex_buffer)); fclose(fp); return;
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

            printf("\nBo dem khoi (tu stream[0..63]): %lu\n", block_counter);

            printf("\n--- Keystream[0..63] KY VONG (tu file) ---\n");
            for (i = 0; i < 64; ++i) { // Đã sửa lỗi 'l'
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
                success_count++; // Tăng biến đếm
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
