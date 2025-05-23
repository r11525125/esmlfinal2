PROJ_NAME=lwip_iperf

STANDALONE = ..


SRCS = 	$(wildcard src/*.c) \
	$(wildcard src/user/arch/*.c) \
	$(wildcard src/api/*.c) \
	$(wildcard src/netif/*.c) \
	$(wildcard src/netif/ppp/*.c) \
	$(wildcard src/netif/ppp/polarssl/*.c) \
	$(wildcard src/core/*.c) \
	$(wildcard src/core/ipv4/*.c) \
	$(wildcard src/*.cpp) \
	$(wildcard src/*.S) \
        ${STANDALONE}/common/start.S\
        ${STANDALONE}/common/trap.S


CFLAGS += -Isrc
CFLAGS += -Isrc/include
CFLAGS += -Isrc/user/arch
CFLAGS += -Isrc/user/
CFLAGS += -DportasmHANDLE_INTERRUPT=external_interrupt_handler

include ${STANDALONE}/common/bsp.mk
include ${STANDALONE}/common/riscv64-unknown-elf.mk
include ${STANDALONE}/common/standalone.mk