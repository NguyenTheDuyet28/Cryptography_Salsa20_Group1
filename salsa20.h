#pragma once
#include<stdint.h>
#include<stddef.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h> 
#include<ctype.h>
#include<stdbool.h>

#define ROUNDS 20

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))      //Dịch vòng trái
#define QR(a, b, c, d)(  \
	b ^= ROTL(a + d, 7), \
	c ^= ROTL(b + a, 9), \
	d ^= ROTL(c + b,13), \
	a ^= ROTL(d + c,18))

uint32_t U8TO32_LITTLE(const uint8_t* p);  // Chuyển 4 bytes liên tiếp thành 1 word (Litte endian)
void U32TO8_LITTLE(uint8_t* p, uint32_t v); // Chuyển 1 word thành 4 bytes (Little endian)
void salsa20_block(uint32_t out[16], uint32_t const in[16]); // Hàm salsa20 block
void clean_stdin(void); //Loại bỏ ký tự \n
int hex_char_to_int(char c); // Chuyển ký tự hex thành int
int hex_string_to_bytes(uint8_t *dst, const char *src, size_t dst_len); // Chuyển chuỗi hex thành mảng byte


