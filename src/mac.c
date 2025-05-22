/*
 * mac.c
 *
 *  Created on: Aug 18, 2020
 *      Author: shchung
 */

#include <string.h>


#include "reg.h"
#include "bsp.h"
#include "mac.h"
#include "common.h"
#include "compatibility.h"


void control_reset (struct cmn_reset *rst)
{
	write_u32(*(uint32_t *)rst, IO_APB_SLAVE_2_APB+0x08);
}

/************************** Function File ***************************/
void MacTxEn(u32 tx_en)
{
	u32 Value;
	//Set Mac TxEn
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & TX_ENA_MASK;
	Value |= (tx_en&0x1)<<0;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Set Mac TxEn.\r\n");
	}
}

/************************** Function File ***************************/
void MacRxEn(u32 rx_en)
{
	u32 Value;
	//Set Mac RxEn
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & RX_ENA_MASK;
	Value |= (rx_en&0x1)<<1;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Set Mac RxEn.\r\n");
	}
}

/************************** Function File ***************************/
void MacSpeedSet(u32 speed)
{
	u32 Value;
	//Set Mac Speed
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & ETH_SPEED_MASK;
	Value |= (speed&0x7)<<16;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Set Mac Speed.\r\n");
	}
}

/************************** Function File ***************************/
void MacLoopbackSet(u32 loopback_en)
{
	u32 Value;
	//Set Mac Loopback
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & LOOP_ENA_MASK;
	Value |= (loopback_en&0x1)<<15;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//command_config Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Set Mac Loopback.\r\n");
	}
}

/************************** Function File ***************************/
void MacIpgSet(u32 ipg)
{
	//Set Mac IPG
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+0x05c), ipg&0x3f);//mac_reg tx_ipg_length Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Set Mac IPG.\r\n");
	}
}

/************************** Function File ***************************/
void MacAddrSet(u32 dst_addr_ins, u32 src_addr_ins)
{
	u32 Value;
	//dst mac addr set
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+DST_MAC_ADDR_HI), DST_MAC_H);//mac_reg mac_addr[47:32]
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+DST_MAC_ADDR_LO), DST_MAC_L);//mac_reg mac_addr[31:0]
	//dst mac addr ins set
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+TX_DST_ADDR_INS), dst_addr_ins);//mac_reg tx_dst_addr_ins
	//src mac addr set
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+MAC_ADDR_HI), SRC_MAC_H);//mac_addr[47:32]
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+MAC_ADDR_LO), SRC_MAC_L);//mac_addr[31:0]
	//src mac addr ins set
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & TX_ADDR_INS_MASK;//mac_reg command_config Reg
	Value |= (src_addr_ins&0x1)<<9;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//command_config Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Set Mac Address.\r\n");
	}
}

/********************************* Function **********************************/
void Pause_XOn()
{
	u32 Value;
	//Set xon_gen 1
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & XON_GEN_MASK;
	Value |= 0x1<<2;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
	//Set xon_gen 0
	Value &= XON_GEN_MASK;
	Value |= 0x0<<2;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
}

/************************** Function File ***************************/
void MacCntClean()
{
	u32 Value;
	//Set cnt_reset 1
	Value = Reg_In32(XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG) & CNT_RST_MASK;
	Value |= 0x80000000;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
	bsp_uDelay(1);
	//Set cnt_reset 0
	Value &= CNT_RST_MASK;
	Value |= 0x0;
	Reg_Out32((XPAR_SYS_AXI_BASEADDR+COMMAND_CONFIG), Value);//mac_reg command_config Reg
	if(PRINTF_EN == 1) {
		bsp_printf("Info : Mac Reset Statistics Counters.\r\n");
	}
}

/************************** Function File ***************************/
void CntMonitor()
{
	bsp_printf("-------------------- \r\n");
	bsp_printf("aFramesTransmittedOK %d\r\n", Reg_In32(XPAR_SYS_AXI_BASEADDR+A_FRAME_TRANSMITTED_OK));
	bsp_printf("aFramesReceivedOK %d\r\n", Reg_In32(XPAR_SYS_AXI_BASEADDR+A_FRAME_RECEIVED_OK));
	bsp_printf("ifInErrors %d\r\n", Reg_In32(XPAR_SYS_AXI_BASEADDR+IF_INDICATES_ERROR));
	bsp_printf("-------------------- \r\n");
}
/************************** Function File ***************************/
void MacRst(u8 MacRst, u8 PhyRst)
{
	struct cmn_reset 	rst;

	memset(&rst,0,sizeof(rst));

	if(MacRst)	rst.mac_rst=1;
	if(PhyRst)	rst.phy_rst=1;

	control_reset(&rst);
	bsp_uDelay(100*1000);
	rst.mac_rst=0;
	rst.phy_rst=0;

	control_reset(&rst);
	bsp_uDelay(100*1000);
}


/************************** Function File ***************************/
void MacNormalInit(u32 speed)
{
	MacRst(1,0);
	MacSpeedSet(speed);
}





