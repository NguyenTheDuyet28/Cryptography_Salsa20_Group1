#define _CRT_SECURE_NO_WARNINGS
#include "run.h"

int main() {
    char mode = ' ';
    printf("Ban co muon nhap tu ban phim hay khong? (y/n): ");

    // Đọc lựa chọn
    if (scanf(" %c", &mode) != 1) {
        printf("Loi doc lua chon.\n");
        return 1;
    }
    // Dọn dẹp bộ đệm stdin
    clean_stdin();

    // Điều hướng logic
    if (mode == 'y' || mode == 'Y') {
        run_user();
    }
    else {
        run_test_vectors();
    }

    return 0;
}
