#pragma once
#include "salsa20.h"

#define MAX_PLAINTEXT_BUFFER 1025 

void salsa20_crypt(uint8_t key[32], int key_len, uint8_t nonce[8],
    uint64_t initial_counter, uint8_t* buffer, size_t length);
void run_user(void); //Chạy chương trình nhập thủ công
void run_test_vectors(void); //Chạy chương trình với test vectors
