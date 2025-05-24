# ============================
# Project: lwip_iperf
# ============================
PROJ_NAME  := lwip_iperf
STANDALONE := ..

# -------------------------------------------------------------------
# 交叉编译器前缀，请根据实际安装修改
# -------------------------------------------------------------------
CROSS_COMPILE ?= riscv-none-embed-

CC      := $(CROSS_COMPILE)gcc
CXX     := $(CROSS_COMPILE)g++
AR      := $(CROSS_COMPILE)ar
LD      := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump
SIZE    := $(CROSS_COMPILE)size

# -------------------------------------------------------------------
# 源文件列表
# -------------------------------------------------------------------
SRCS := \
	$(wildcard src/*.c) \
	$(wildcard src/*.cc) \
	$(wildcard src/*.cpp) \
	$(wildcard src/*.S) \
	$(wildcard src/tensorflow/lite/*.c) \
	$(wildcard src/tensorflow/lite/c/*.c) \
	$(wildcard src/tensorflow/lite/core/api/*.cc) \
	$(wildcard src/tensorflow/lite/kernels/*.cc) \
	$(wildcard src/tensorflow/lite/kernels/internal/*.cc) \
	$(wildcard src/tensorflow/lite/kernels/internal/optimized/*.cc) \
	$(wildcard src/tensorflow/lite/kernels/internal/reference/*.cc) \
	$(wildcard src/tensorflow/lite/kernels/internal/reference/integer_ops/*.cc) \
	$(wildcard src/tensorflow/lite/micro/*.cc) \
	$(wildcard src/tensorflow/lite/micro/kernels/*.cc) \
	$(wildcard src/tensorflow/lite/micro/memory_planner/*.cc) \
	$(wildcard src/tensorflow/lite/schema/*.cc) \
	$(wildcard src/platform/*/*.cc) \
	$(wildcard src/platform/*/*.c) \
	$(wildcard src/platform/*/*/*.cc) \
	$(wildcard src/platform/*/*/*.c) \
	$(wildcard src/model/*.cc) \
	$(wildcard src/user/arch/*.c) \
	$(wildcard src/api/*.c) \
	$(wildcard src/netif/*.c) \
	$(wildcard src/netif/ppp/*.c) \
	$(wildcard src/netif/ppp/polarssl/*.c) \
	$(wildcard src/core/*.c) \
	$(wildcard src/core/ipv4/*.c) \
	${STANDALONE}/common/start.S \
	${STANDALONE}/common/trap.S

# -------------------------------------------------------------------
# 编译选项
# -------------------------------------------------------------------
CFLAGS   := -O2 -std=gnu11 -Wall -DTF_LITE_STATIC_MEMORY \
	-Isrc \
	-Isrc/include \
	-Isrc/user/arch \
	-Isrc/user \
	-DportasmHANDLE_INTERRUPT=external_interrupt_handler \
	-Isrc/tensorflow/third_party/flatbuffers/include \
	-Isrc/tensorflow/third_party/gemmlowp \
	-Isrc/tensorflow/third_party/ruy

CXXFLAGS := -O2 -std=gnu++11 -fstrict-aliasing -fno-rtti -fno-exceptions \
	-fno-threadsafe-statics -fmessage-length=0 -Wall -DTF_LITE_STATIC_MEMORY \
	$(filter -I%,$(CFLAGS))

LDFLAGS  :=

# -------------------------------------------------------------------
# 包含 BSP、工具链、Standalone 支持
# -------------------------------------------------------------------
include ${STANDALONE}/common/bsp.mk
include ${STANDALONE}/common/riscv64-unknown-elf.mk
include ${STANDALONE}/common/tinyml_standalone.mk

LIBS    += ${STANDALONE}/common/tinyml_lib.a

# -------------------------------------------------------------------
# 产物和规则
# -------------------------------------------------------------------
OBJDIR := build/obj_files
OBJS   := $(patsubst src/%.c,$(OBJDIR)/%.o,$(wildcard src/*.c)) \
          $(patsubst src/%.cc,$(OBJDIR)/%.o,$(wildcard src/*.cc)) \
          $(patsubst src/%.cpp,$(OBJDIR)/%.o,$(wildcard src/*.cpp)) \
          $(patsubst src/%.S,$(OBJDIR)/%.o,$(wildcard src/*.S))

.PHONY: all clean

all: $(PROJ_NAME).elf

$(PROJ_NAME).elf: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(SIZE) $@

# C 文件
$(OBJDIR)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# C++ 文件（.cc/.cpp）
$(OBJDIR)/%.o: src/%.cc
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/%.o: src/%.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 汇编文件
$(OBJDIR)/%.o: ${STANDALONE}/common/%.S
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(PROJ_NAME).elf
