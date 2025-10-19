#include "salsa20.h"

uint32_t U8TO32_LITTLE(const uint8_t* p)
{
	return
		(uint32_t)(p[0]) |
		((uint32_t)(p[1]) << 8) |
		((uint32_t)(p[2]) << 16) |
		((uint32_t)(p[3]) << 24);
}

void U32TO8_LITTLE(uint8_t* p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

void salsa20_block(uint32_t out[16], uint32_t const in[16])
{
	int i;
	uint32_t x[16];
	for (i = 0; i < 16; ++i)
		x[i] = in[i];
	for (i = 0; i < ROUNDS; i += 2) {
		// Odd round (Column)
		QR(x[0], x[4], x[8], x[12]);
		QR(x[5], x[9], x[13], x[1]);
		QR(x[10], x[14], x[2], x[6]);
		QR(x[15], x[3], x[7], x[11]);
		// Even round (Row)
		QR(x[0], x[1], x[2], x[3]);
		QR(x[5], x[6], x[7], x[4]);
		QR(x[10], x[11], x[8], x[9]);
		QR(x[15], x[12], x[13], x[14]);
	}
	for (i = 0; i < 16; ++i)
		out[i] = x[i] + in[i];
}


void clean_stdin(void) {
	int c;
	while ((c = getchar()) != '\n' && c != EOF);
}

int hex_char_to_int(char c) {
	c = (char)tolower(c);
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1; // Lỗi
}

int hex_string_to_bytes(uint8_t* dest, const char* src, size_t dest_len) {
	size_t len = strlen(src);
	if (len % 2 != 0 || len / 2 != dest_len) {
		printf("Loi: Chuoi hex co do dai khong hop le (can %zu ky tu, nhan duoc %zu).\n", dest_len * 2, len);
		return -1; // Chuỗi hex phải có độ dài chẵn
	}

	for (size_t i = 0; i < dest_len; ++i) {
		int high = hex_char_to_int(src[i * 2]);
		int low = hex_char_to_int(src[i * 2 + 1]);

		if (high == -1 || low == -1) {
			printf("Loi: Chuoi hex chua ky tu khong hop le.\n");
			return -1; // Ký tự không hợp lệ
		}
		dest[i] = (uint8_t)((high << 4) | low);
	}
	return 0; // Thành công
}