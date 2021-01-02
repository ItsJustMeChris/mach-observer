BUILD_DIR?=./build

CC=clang++

all: mach-observer

mach-observer: $(BUILD_DIR)
	$(CC) main.cpp -o $(BUILD_DIR)/mach-observer

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
