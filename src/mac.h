
#ifndef SRC_MAC_H_
#define SRC_MAC_H_

#include "bsp.h"

#define configIP_ADDR0		192
#define configIP_ADDR1		168
#define configIP_ADDR2		31
#define configIP_ADDR3		55

#define configMAC_ADDR0 0x00
#define configMAC_ADDR1 0x11
#define configMAC_ADDR2 0x22
#define configMAC_ADDR3 0x33
#define configMAC_ADDR4 0x44
#define configMAC_ADDR5 0x41



/************************** Project Header File ***************************/
#define PRINTF_EN   0
#define TEST_MODE   0//0:Normal Mode; 1:Link partner Test Mode;

#define PAT_NUM 	0
#define PAT_DLEN	8
#define PAT_IPG		4095//4095//255
#define PAT_TYPE	0//0:UDP Pattern; //1:MAC Pattern;
#define DST_MAC_H 	0xffff
#define DST_MAC_L 	0xffffffff
#define SRC_MAC_H 	(configMAC_ADDR5<<8)|configMAC_ADDR4
#define SRC_MAC_L 	(configMAC_ADDR3<<24)|(configMAC_ADDR2<<16)|(configMAC_ADDR1<<8)|configMAC_ADDR0//0x5e0060c8
#define SRC_IP 		(configIP_ADDR3<<24)|(configIP_ADDR2<<16)|(configIP_ADDR1<<8)|configIP_ADDR0
#define DST_IP 		0xc0a80165
#define SRC_PORT	0x0521
#define DST_PORT	0x2715

/************************** System Header File ***************************/
#define PHY_ADDR   0x0

/************************** HW Header File ***************************/
#define BASE IO_APB_SLAVE_0_APB
#define XPAR_SYS_AXI_BASEADDR IO_APB_SLAVE_0_APB

/************************** Application Header File ***************************/
#define TX_ENA_MASK    		0xFFFFFFFE
#define RX_ENA_MASK    		0xFFFFFFFD
#define XON_GEN_MASK 		0xFFFFFFFB
#define PROMIS_EN_MASK   	0xFFFFFFEF
#define PAD_EN_MASK   		0xFFFFFFDF
#define CRC_FWD_MASK   		0xFFFFFFBF
#define PAUSE_IGNORE_MASK   0xFFFFFEFF
#define TX_ADDR_INS_MASK   	0xFFFFFBFF
#define LOOP_ENA_MASK   	0xFFFF7FFF
#define ETH_SPEED_MASK   	0xFFF8FFFF
#define XOFF_GEN_MASK 		0xFFBFFFFF
#define CNT_RST_MASK 		0x7FFFFFFF


void MacTxEn(u32 tx_en);
void MacRxEn(u32 rx_en);
void MacSpeedSet(u32 speed);
void MacLoopbackSet(u32 loopback_en);
void MacIpgSet(u32 ipg);
void MacAddrSet(u32 dst_addr_ins, u32 src_addr_ins);
void Pause_XOn();
void MacCntClean();
void CntMonitor();
void MacNormalInit(u32 speed);

struct cmn_reset {
	uint8_t mac_rst : 1;
	uint8_t phy_rst : 1;
	uint32_t rs	: 30;
} cmn_reset;

/*
struct cmn_rx_ctrl {
	uint8_t rx_rd 		: 1;
	uint8_t rs0		: 3;
	uint8_t rx_intr_mask 	: 1;
	uint8_t rs1		: 3;
	uint8_t rx_ready_rl 	: 1;
	uint32_t rs 		: 23;
} cmn_rx_ctrl;
*/
void control_reset (struct cmn_reset *rst);
//struct cmn_rx_ctrl control_rx (struct cmn_rx_ctrl *ctrl);

void MacRst(u8 MacRst, u8 PhyRst);

#endif
