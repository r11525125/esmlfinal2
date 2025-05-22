###############################################################################
# pkt_inspector – Feature-dumper firmware (lwip_final)
###############################################################################

PROJ_NAME  := lwip_final          # 產出 build/lwip_final.elf
STANDALONE := ..

# ---------------- source list -----------------------------------------------
SRCS := \
    src/main.c \
    src/extract_features.c \
    src/common.c \
    src/mac.c \
    src/rtl8211fd_drv.c \
    $(STANDALONE)/common/start.S \
    $(STANDALONE)/common/trap.S

# ---------------- include paths ---------------------------------------------
CFLAGS += -Isrc/include
CFLAGS += -Isrc
CFLAGS += -Isrc/user/arch
CFLAGS += -I$(STANDALONE)/driver
CFLAGS += -I$(STANDALONE)/bsp/efnix/EfxSapphireSoc/include
CFLAGS += -DportasmHANDLE_INTERRUPT=external_interrupt_handler
CFLAGS += -Os -g

# ---------------- BSP / linker / GCC rules ----------------------------------
include $(STANDALONE)/common/bsp.mk
include $(STANDALONE)/common/riscv64-unknown-elf.mk
include $(STANDALONE)/common/standalone.mk

# ---------------- 補一條規則，把 .elf 複製成無副檔名 ------------------------
build/$(PROJ_NAME): build/$(PROJ_NAME).elf
	@mkdir -p build
	@cp  $<  $@
