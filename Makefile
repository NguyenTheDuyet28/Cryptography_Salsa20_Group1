# Trình biên dịch(GNU C Compiler)
CC = gcc

# Các cờ (flags) cho trình biên dịch:
# -Wall: Bật tất cả các cảnh báo
# -g: Thêm thông tin gỡ lỗi (cho GDB)
# -o: Chỉ định tên file đầu ra
CFLAGS = -Wall -g

# File thực thi
EXECUTABLE = Salsa20exe

# File mã nguồn (.c)
SOURCES = main.c run.c salsa20.c

# Quy tắc mặc định: Chạy khi gõ "make"
# Phụ thuộc vào file thực thi
all: $(EXECUTABLE)

# Quy tắc chính: Cách để tạo ra file thực thi
# Phụ thuộc vào tất cả các file mã nguồn
$(EXECUTABLE): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

# Quy tắc "clean": Dọn dẹp dự án
# Xóa file thực thi đã tạo
clean:
	rm -f $(EXECUTABLE)
