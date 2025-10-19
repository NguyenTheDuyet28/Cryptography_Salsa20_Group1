#define _CRT_SECURE_NO_WARNINGS
#include "run.h"
#include <string.h> 

#define MAX_KEY_HEX 65  // 32*2 + 1
#define MAX_NONCE_HEX 17 // 8*2 + 1
#define MAX_PLAIN_HEX (MAX_SIZE * 2 + 1) // 64*2 + 1
#define MAX_STREAM_HEX_BUFFER 200

// Hàm thực hiện mã hóa/giải mã Salsa20
void perform_salsa20(uint8_t key[32], int key_len, uint8_t nonce[8],
    uint64_t block_counter, uint8_t* plaintext, size_t length)
{
    size_t i;
    const uint8_t constants[17] = "expand 32-byte k";
    const uint8_t constants_16[17] = "expand 16-byte k";
    uint32_t input[16];

    // Thiết lập ma trận trạng thái ban đầu
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
        // Lặp lại khóa cho khóa 16 byte
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

    // Tạo khối keystream
    uint32_t keystream_words[16];
    salsa20_block(keystream_words, input);

    uint8_t keystream_bytes[MAX_SIZE];
    for (i = 0; i < 16; ++i) {
        U32TO8_LITTLE(keystream_bytes + i * 4, keystream_words[i]);
    }

    // Mã hóa plaintext
    uint8_t ciphertext[MAX_SIZE + 1] = { 0 };
    for (i = 0; i < length; ++i) {
        ciphertext[i] = plaintext[i] ^ keystream_bytes[i];
    }
    ciphertext[length] = '\0'; // Kết thúc chuỗi null

    // Giải mã ciphertext (để minh họa)
    uint8_t decrypted[MAX_SIZE + 1] = { 0 };
    for (i = 0; i < length; ++i) {
        decrypted[i] = ciphertext[i] ^ keystream_bytes[i];
    }
    decrypted[length] = '\0'; // Kết thúc chuỗi null

    // In kết quả
    printf("\n--- INPUT---\n");
    // In khóa dưới dạng ASCII (như đã nhập) và dạng Hex
    printf("Khoa (%d byte - Dang ASCII): %.*s\n", key_len, key_len, key);
    printf("Khoa (%d byte - Dang Hex): \n", key_len);
    for (i = 0; i < (size_t)key_len; i++) printf("%02x", key[i]);
    printf("\nNonce (8 byte - Dang Hex): \n");
    for (i = 0; i < 8; i++) printf("%02x", nonce[i]);
    printf("\nBlock Counter: %llu\n", block_counter);

    printf("Plaintext (Dang chuoi): %s\n", plaintext);
    printf("Plaintext (%zu byte - Dang Hex):\n", length);
    for (size_t j = 0; j < length; ++j) {
        printf("%02x ", plaintext[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }
    if (length % 16 != 0) printf("\n"); // Đảm bảo xuống dòng nếu không đủ 16 byte cuối

    printf("\nKeystream (64 byte - Dang Hex):\n");
    for (size_t j = 0; j < MAX_SIZE; ++j) {
        printf("%02x ", keystream_bytes[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }

    printf("\n--- OUTPUT ---\n");
    printf("Ciphertext (%zu byte - Dang Hex):\n", length);
    for (size_t j = 0; j < length; ++j) {
        printf("%02x ", ciphertext[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }
    if (length % 16 != 0) printf("\n"); // Đảm bảo xuống dòng

    printf("\nDa giai ma (dang chuoi): %s\n", decrypted);

    // Xác minh giải mã
    if (memcmp(plaintext, decrypted, length) == 0) {
        printf("\n=> Plaintext khoi phuc dung.\n");
    }
    else {
        printf("\n=> Plaintext khoi phuc sai.\n");
    }
}

// Hàm chạy với đầu vào từ bàn phím
void run_user(void) {
    uint8_t key[32] = { 0 };
    uint8_t nonce[8] = { 0 };
    uint64_t block_counter = 0;
    uint8_t plaintext[MAX_SIZE + 1] = { 0 };
    size_t plaintext_len = 0;
    int key_len = 0;
    char key_input_buffer[33]; // Bộ đệm cho nhập khóa ASCII (tối đa 32 ký tự + null)

    printf("Chon do dai khoa (16 hoac 32 byte): ");
    if (scanf("%d", &key_len) != 1) {
        printf("Loi: Nhap khong hop le.\n"); clean_stdin(); return;
    }
    clean_stdin(); // Xóa ký tự xuống dòng còn lại

    if (key_len != 16 && key_len != 32) {
        printf("Do dai khoa khong hop le.\n"); return;
    }

    //Nhập khoá dạng mã ASCII
    printf("Nhap khoa (dang ASCII, chinh xac %d ky tu): ", key_len);
    // Đọc chính xác key_len ký tự vào bộ đệm tạm thời để tránh tràn bộ đệm
    if (fgets(key_input_buffer, sizeof(key_input_buffer), stdin) == NULL) {
        printf("Loi doc khoa.\n"); return;
    }
    // Xóa ký tự xuống dòng '\n' có thể có ở cuối do fgets
    key_input_buffer[strcspn(key_input_buffer, "\n")] = 0;

    // Kiểm tra xem đã nhập đúng số lượng ký tự chưa
    if (strlen(key_input_buffer) != (size_t)key_len) {
        printf("Loi: Can nhap %d ky tu khoa, nhung da nhan duoc %zu.\n", key_len, strlen(key_input_buffer));
        return;
    }
    // Sao chép trực tiếp các ký tự ASCII từ bộ đệm vào mảng khóa
    memcpy(key, key_input_buffer, key_len);


    char nonce_hex[MAX_NONCE_HEX];
    printf("Nhap nonce (dang hex, 16 ky tu): ");
    // Giới hạn kích thước đọc để tránh tràn bộ đệm nonce_hex
    if (scanf("%16s", nonce_hex) != 1) {
        printf("Loi doc nonce.\n"); clean_stdin(); return;
    }
    clean_stdin();
    // Chuyển đổi nonce từ hex sang byte
    if (hex_string_to_bytes(nonce, nonce_hex, 8) != 0) return;

    printf("Nhap bo dem khoi (vi du: 7): ");
    if (scanf("%llu", &block_counter) != 1) {
        printf("Loi doc bo dem khoi.\n"); clean_stdin(); return;
    }
    clean_stdin();

    printf("Nhap plaintext (toi da %d byte):\n", MAX_SIZE);
   
    if (fgets((char*)plaintext, MAX_SIZE + 1, stdin) == NULL) {
        plaintext[0] = '\0'; // Xử lý lỗi hoặc chuỗi rỗng
    }
    // Xóa ký tự xuống dòng '\n' có thể có ở cuối
    plaintext[strcspn((char*)plaintext, "\n")] = 0;
    plaintext_len = strlen((const char*)plaintext);


    perform_salsa20(key, key_len, nonce, block_counter, plaintext, plaintext_len);
}

// Hàm chạy các test vector từ file
void run_test_vectors(void) {
    uint8_t key[32] = { 0 };
    uint8_t nonce[8] = { 0 };
    uint64_t block_counter = 0; // Sẽ được đặt là 0 khi đọc stream[0..63]
    int key_len = 0;
    uint8_t expected_keystream[64] = { 0 }; // Đọc từ file
    bool key_found = false, nonce_found = false, stream_found = false;

    char filename[100] = { 0 };
    printf("Nhap ten file test vector (vi du: test_vector256.txt): ");
    if (scanf("%99s", filename) != 1) {
        printf("Loi doc ten file.\n"); clean_stdin(); return;
    }
    clean_stdin();

    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Loi: Khong the mo file %s\n", filename);
        return;
    }

    char line[256];                 // Bộ đệm đọc dòng
    char hex_buffer[MAX_STREAM_HEX_BUFFER] = { 0 }; // Bộ đệm tích lũy chuỗi hex

    printf("Dang doc file %s...\n", filename);

    while (fgets(line, sizeof(line), fp) != NULL) {
        // Loại bỏ khoảng trắng đầu/cuối dòng
        char* start = line;
        while (isspace((unsigned char)*start)) start++;
        char* end = start + strlen(start) - 1;
        while (end > start && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';

        // Bỏ qua dòng trống, dòng header "[source...]", dòng "Set...", "Test vectors...", "==="
        if (strlen(start) == 0 || start[0] == '[' || strncmp(start, "Set", 3) == 0 || strncmp(start, "Test vectors", 12) == 0 || start[0] == '=') {
            continue;
        }

        // --- Xử lý Key ---
        if (strncmp(start, "key = ", 6) == 0 && !key_found) {
            memset(hex_buffer, 0, sizeof(hex_buffer)); // Xóa buffer trước khi dùng
            // Nối phần hex của dòng hiện tại
            strncat(hex_buffer, start + 6, sizeof(hex_buffer) - strlen(hex_buffer) - 1);

            // Kiểm tra các dòng tiếp theo có phải là phần tiếp của key không
            long current_pos = ftell(fp); // Lưu vị trí hiện tại
            while (fgets(line, sizeof(line), fp) != NULL) {
                char* next_start = line;
                while (isspace((unsigned char)*next_start)) next_start++;
                // Nếu dòng tiếp không bắt đầu bằng nhãn quen thuộc và không phải header/set/dòng trống/dấu bằng, coi đó là phần tiếp của key
                if (strlen(next_start) > 0 && strncmp(next_start, "IV = ", 5) != 0 && strncmp(next_start, "stream[", 7) != 0 && strncmp(next_start, "xor-digest", 10) != 0 && strncmp(next_start, "Set", 3) != 0 && next_start[0] != '[' && next_start[0] != '=') {
                    char* next_end = next_start + strlen(next_start) - 1;
                    while (next_end > next_start && isspace((unsigned char)*next_end)) next_end--;
                    *(next_end + 1) = '\0';
                    // Kiểm tra xem có đủ chỗ trong buffer không trước khi nối
                    if (strlen(hex_buffer) + strlen(next_start) < sizeof(hex_buffer)) {
                        strncat(hex_buffer, next_start, sizeof(hex_buffer) - strlen(hex_buffer) - 1);
                        current_pos = ftell(fp); // Cập nhật vị trí đã đọc thành công
                    }
                    else {
                        printf("Loi: Buffer khong du cho cho key hex.\n"); fclose(fp); return;
                    }
                }
                else {
                    // Không phải phần tiếp của key, trả lại dòng đã đọc và dừng
                    fseek(fp, current_pos, SEEK_SET);
                    break;
                }
            }
            // Chuyển đổi key hex
            key_len = (int)strlen(hex_buffer) / 2;
            if (key_len != 16 && key_len != 32) {
                printf("Loi: Key hex '%s' co do dai khong hop le (%d byte).\n", hex_buffer, key_len); fclose(fp); return;
            }
            if (hex_string_to_bytes(key, hex_buffer, (size_t)key_len) != 0) { fclose(fp); return; }
            key_found = true;
            printf("  -> Da tim thay key (%d byte).\n", key_len);
        }
        // --- Xử lý Nonce (IV) ---
        else if (strncmp(start, "IV = ", 5) == 0 && !nonce_found) {
            memset(hex_buffer, 0, sizeof(hex_buffer)); // Xóa buffer
            strncpy(hex_buffer, start + 5, sizeof(hex_buffer) - 1);
            if (strlen(hex_buffer) != 16) {
                printf("Loi: IV hex '%s' phai co 16 ky tu.\n", hex_buffer); fclose(fp); return;
            }
            if (hex_string_to_bytes(nonce, hex_buffer, 8) != 0) { fclose(fp); return; }
            nonce_found = true;
            printf("  -> Da tim thay IV/Nonce.\n");
        }
        // --- Xử lý Keystream block 0 ---
        else if (strncmp(start, "stream[0..63] = ", 16) == 0 && !stream_found) {
            block_counter = 0; // Block 0
            memset(hex_buffer, 0, sizeof(hex_buffer)); // Xóa buffer
            strncat(hex_buffer, start + 16, sizeof(hex_buffer) - strlen(hex_buffer) - 1);

            // Đọc các dòng tiếp theo cho keystream (thường kéo dài nhiều dòng)
            long current_pos = ftell(fp);
            while (fgets(line, sizeof(line), fp) != NULL) {
                char* next_start = line;
                while (isspace((unsigned char)*next_start)) next_start++;
                // Nếu không phải nhãn, coi là phần tiếp của stream
                if (strlen(next_start) > 0 && strncmp(next_start, "key = ", 6) != 0 && strncmp(next_start, "IV = ", 5) != 0 && strncmp(next_start, "stream[", 7) != 0 && strncmp(next_start, "xor-digest", 10) != 0 && strncmp(next_start, "Set", 3) != 0 && next_start[0] != '[' && next_start[0] != '=') {
                    char* next_end = next_start + strlen(next_start) - 1;
                    while (next_end > next_start && isspace((unsigned char)*next_end)) next_end--;
                    *(next_end + 1) = '\0';
                    if (strlen(hex_buffer) + strlen(next_start) < sizeof(hex_buffer)) {
                        strncat(hex_buffer, next_start, sizeof(hex_buffer) - strlen(hex_buffer) - 1);
                        current_pos = ftell(fp); // Cập nhật vị trí đã đọc thành công
                    }
                    else {
                        printf("Loi: Buffer khong du cho cho stream hex.\n"); fclose(fp); return;
                    }
                }
                else {
                    // Trả lại dòng và dừng đọc stream
                    fseek(fp, current_pos, SEEK_SET);
                    break;
                }
            }

            // Chuyển đổi stream hex
            if (strlen(hex_buffer) != 128) {
                printf("Loi: stream[0..63] hex '%s' phai co 128 ky tu, tim thay %zu.\n", hex_buffer, strlen(hex_buffer)); fclose(fp); return;
            }
            if (hex_string_to_bytes(expected_keystream, hex_buffer, 64) != 0) { fclose(fp); return; }
            stream_found = true;
            printf("  -> Da tim thay stream[0..63].\n");
        }

        // Nếu đã tìm đủ thông tin cho vector đầu tiên, dừng đọc file
        if (key_found && nonce_found && stream_found) {
            break;
        }
    }
    fclose(fp);

    // Kiểm tra xem có đọc đủ thông tin không
    if (!key_found || !nonce_found || !stream_found) {
        printf("\nLoi: Khong tim thay du key, IV, và stream[0..63] trong file theo dung dinh dang.\n");
        return;
    }

    // --- Logic Xác minh ---
    uint32_t input[16];
    uint32_t generated_keystream_words[16];
    uint8_t generated_keystream_bytes[64];
    const uint8_t constants[17] = "expand 32-byte k";
    const uint8_t constants_16[17] = "expand 16-byte k";
    size_t i;

    // Xây dựng ma trận input (sao chép từ perform_salsa20)
    if (key_len == 32) {
        input[0] = U8TO32_LITTLE(constants + 0); input[1] = U8TO32_LITTLE(key + 0); input[2] = U8TO32_LITTLE(key + 4); input[3] = U8TO32_LITTLE(key + 8); input[4] = U8TO32_LITTLE(key + 12); input[5] = U8TO32_LITTLE(constants + 4); input[10] = U8TO32_LITTLE(constants + 8); input[11] = U8TO32_LITTLE(key + 16); input[12] = U8TO32_LITTLE(key + 20); input[13] = U8TO32_LITTLE(key + 24); input[14] = U8TO32_LITTLE(key + 28); input[15] = U8TO32_LITTLE(constants + 12);
    }
    else { // key_len == 16
        input[0] = U8TO32_LITTLE(constants_16 + 0); input[1] = U8TO32_LITTLE(key + 0); input[2] = U8TO32_LITTLE(key + 4); input[3] = U8TO32_LITTLE(key + 8); input[4] = U8TO32_LITTLE(key + 12); input[5] = U8TO32_LITTLE(constants_16 + 4); input[10] = U8TO32_LITTLE(constants_16 + 8); input[11] = U8TO32_LITTLE(key + 0); input[12] = U8TO32_LITTLE(key + 4); input[13] = U8TO32_LITTLE(key + 8); input[14] = U8TO32_LITTLE(key + 12); input[15] = U8TO32_LITTLE(constants_16 + 12);
    }
    input[6] = U8TO32_LITTLE(nonce + 0); input[7] = U8TO32_LITTLE(nonce + 4);
    input[8] = (uint32_t)(block_counter & 0xffffffff); input[9] = (uint32_t)(block_counter >> 32);

    // Tính toán keystream
    salsa20_block(generated_keystream_words, input);
    for (i = 0; i < 16; ++i) {
        U32TO8_LITTLE(generated_keystream_bytes + i * 4, generated_keystream_words[i]);
    }

    // In và So sánh
    printf("\n--- DAU VAO DA DOC TU FILE ---\n");
    printf("Khoa (%d byte - Dang Hex): \n", key_len);
    for (i = 0; i < (size_t)key_len; i++) printf("%02x", key[i]);
    printf("\nNonce (IV) (8 byte - Dang Hex): \n");
    for (i = 0; i < 8; i++) printf("%02x", nonce[i]);
    printf("\nBo dem khoi (tu stream[0..63]): %llu\n", block_counter);

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

    // So sánh kết quả
    if (memcmp(expected_keystream, generated_keystream_bytes, 64) == 0) {
        printf("\n=> XAC MINH THANH CONG: Keystream tinh toan khop voi file.\n");
    }
    else {
        printf("\n=> XAC MINH THAT BAI: Keystream tinh toan khong khop voi file.\n");
    }
}