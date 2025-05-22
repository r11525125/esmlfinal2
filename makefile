###############################################################################
# pkt_inspector makefile  —  build pkt_inspector.elf
###############################################################################

PROJ_NAME := pkt_inspector

# ←←← 根據實際路徑調整；這表示「上一層」
STANDALONE := ..

# -------- source files ------------------------------------------------------
SRCS := \
    src/main.c \
    src/extract_features.c \
    src/common.c \
    src/mac.c \
    src/rtl8211fd_drv.c \
    ${STANDALONE}/common/start.S \
    ${STANDALONE}/common/trap.S

# -------- include paths -----------------------------------------------------
CFLAGS += -Isrc/include
CFLAGS += -Isrc
CFLAGS += -I${STANDALONE}/driver
CFLAGS += -I${STANDALONE}/bsp/efnix/EfxSapphireSoc/include
CFLAGS += -Os -g
CFLAGS += -DportasmHANDLE_INTERRUPT=external_interrupt_handler

# -------- bring in BSP / linker / gcc rules ---------------------------------
include ${STANDALONE}/common/bsp.mk
include ${STANDALONE}/common/riscv64-unknown-elf.mk
include ${STANDALONE}/common/standalone.mk
