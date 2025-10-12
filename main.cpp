#include<stdint.h>
#include<stddef.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h> 

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))      //Dịch trái vòng
#define QR(a, b, c, d)(  \
	b ^= ROTL(a + d, 7), \
	c ^= ROTL(b + a, 9), \
	d ^= ROTL(c + b,13), \
	a ^= ROTL(d + c,18))
#define ROUNDS 20
#define MAX_SIZE 64 // Plaintext tối đa 64 bytes

// Hàm chuyển 4 bytes liên tiếp thành 1 từ 32 - bit theo little endian
static uint32_t U8TO32_LITTLE(const uint8_t* p)
{
	return
		(uint32_t)(p[0]) |
		((uint32_t)(p[1]) << 8) |
		((uint32_t)(p[2]) << 16) |
		((uint32_t)(p[3]) << 24);
}

// Hàm chuyển 1 từ 32-bit thành 4 bytes theo little endian
static void U32TO8_LITTLE(uint8_t* p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

// Double-round của hàm salsa20
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

int main() {
	int i;
	uint8_t key[32] = { 0 };
	uint8_t nonce[8] = { 3,1,4,1,5,9,2,6 };
	uint64_t block = 7;
	// Khai báo hằng số 16 byte
	const uint8_t constants[17] = "expand 32-byte k";

	
	uint8_t plaintext[MAX_SIZE + 1];
	printf("Nhap plaintext (toi da %d bytes):\n", MAX_SIZE);
	// Dùng scanf với %64[^\n] để đọc tối đa 64 ký tự (bao gồm cả dấu cách) cho đến khi gặp \n
	if (scanf("%64[^\n]", plaintext) != 1) {
		// Xử lý trường hợp người dùng chỉ nhấn Enter (chuỗi rỗng)
		plaintext[0] = '\0';
	}
	// Dọn dẹp buffer nếu có ký tự thừa còn lại trong luồng nhập
	int c;
	while ((c = getchar()) != '\n' && c != EOF);

	int length = strlen((const char*)plaintext); // length = 59
	printf("Plaintext length: %d bytes\n", length);

	for (i = 0; i < 32; ++i) key[i] = (uint8_t)i; // Khởi tạo key

	// Khởi tạo ma trận 4x4 (Input cho hàm salsa20_block)
	uint32_t input[16];
	input[0] = U8TO32_LITTLE(constants + 0);
	input[1] = U8TO32_LITTLE(key + 0);
	input[2] = U8TO32_LITTLE(key + 4);
	input[3] = U8TO32_LITTLE(key + 8);
	input[4] = U8TO32_LITTLE(key + 12);
	input[5] = U8TO32_LITTLE(constants + 4);
	input[6] = U8TO32_LITTLE(nonce + 0);
	input[7] = U8TO32_LITTLE(nonce + 4);
	input[8] = (uint32_t)(block & 0xffffffff);
	input[9] = (uint32_t)(block >> 32);
	input[10] = U8TO32_LITTLE(constants + 8);
	input[11] = U8TO32_LITTLE(key + 16);
	input[12] = U8TO32_LITTLE(key + 20);
	input[13] = U8TO32_LITTLE(key + 24);
	input[14] = U8TO32_LITTLE(key + 28);
	input[15] = U8TO32_LITTLE(constants + 12);

	// Tạo keystream (16 words)
	uint32_t keystream_words[16];
	salsa20_block(keystream_words, input);

	// Chuyển 16 words thành 64 bytes theo little endian
	uint8_t keystream_bytes[MAX_SIZE];
	for (i = 0; i < 16; ++i) {
		U32TO8_LITTLE(keystream_bytes + i * 4, keystream_words[i]);
	}

	// Ciphertext = Plaintext XOR Keystream (byte-by-byte)
	uint8_t ciphertext[65] = { 0 };
	for (i = 0; i < length; ++i) { 
		ciphertext[i] = plaintext[i] ^ keystream_bytes[i];
	}

	// Đảm bảo chuỗi Ciphertext được kết thúc bằng \0 ngay sau dữ liệu
	ciphertext[length] = '\0';


	// Deciphertext = Ciphertext XOR Keystream (byte-by-byte)
	uint8_t decrypted[65] = { 0 };
	for (i = 0; i < length; ++i) {
		decrypted[i] = ciphertext[i] ^ keystream_bytes[i];
	}
	//Đảm bảo chuỗi Decrypted được kết thúc bằng \0 ngay sau dữ liệu (tại index 59)
	decrypted[length] = '\0';

	printf("\nPlaintext: %s\n", plaintext);

	printf("\nKeystream (64 bytes - Hex):\n");
	for (int j = 0; j < MAX_SIZE; ++j) {
		printf("%02x ", keystream_bytes[j]);
		if ((j + 1) % 16 == 0) printf("\n");
	}

	// In ciphertext dưới dạng hex
	printf("\nCiphertext (%d bytes - Hex):\n", length);
	for (int j = 0; j < length; ++j) {
		printf("%02x ", ciphertext[j]);
		if ((j + 1) % 16 == 0) printf("\n");
	}

	// In decrypted (đã khôi phục) dưới dạng chuỗi
	printf("\nDecrypted: %s\n", decrypted);

	// Kiểm tra tính chính xác
	if (memcmp(plaintext, decrypted, length) == 0) {
		printf("\n=> Plaintext khoi phuc dung\n");
	}
	else {
		printf("\n=> Plaintext khoi phuc sai\n");
	}

	return 0;
}

