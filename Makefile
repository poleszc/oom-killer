CC = gcc
CLANG = clang
BPFTOOL = bpftool

CFLAGS = -g -Wall
LIBS = -lbpf -lelf -lz

TARGET = oomkiller
SRC_DIR = src
BUILD_DIR = build

USER_SRC = $(SRC_DIR)/oom_killer.c
BPF_SRC = $(SRC_DIR)/oom_killer.bpf.c

BPF_OBJ = $(BUILD_DIR)/oom_killer.bpf.o
SKEL_HEADER = $(SRC_DIR)/oom_killer.skel.h
VMLINUX_H = $(SRC_DIR)/vmlinux.h

.PHONY: all clean run

all: install $(TARGET)

install:
	sudo apt install clang libbpf-dev bpftool

clean:
	rm -f $(TARGET)
	rm -f $(SKEL_HEADER) $(VMLINUX_H)
	rm -rf $(BUILD_DIR)
	make -C tests clean

$(TARGET): $(USER_SRC) $(SKEL_HEADER)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -o $@ $(LIBS)

$(SKEL_HEADER): $(BPF_OBJ)
	sudo $(BPFTOOL) gen skeleton $< name oom_killer > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	@mkdir -p $(@D)
	$(CLANG) -g -Og -target bpf -I$(SRC_DIR) -c $< -o $@

$(VMLINUX_H):
	sudo $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

run: all
	sudo ./$(TARGET)