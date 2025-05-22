/*
 * commom.h
 *
 *  Created on: Aug 18, 2020
 *      Author: shchung
 */

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include "bsp.h"
#include "compatibility.h"

#define DMASG_BASE IO_APB_SLAVE_1_APB
#define DMASG_OP0		0
#define DMASG_CHANNEL0 	DMASG_OP0
#define DMASG_OP1		1
#define DMASG_CHANNEL1 	DMASG_OP1
#define DMASG_OP2		2
#define DMASG_CHANNEL2 	DMASG_OP2

#define Speed_1000Mhz		0x04
#define Speed_100Mhz		0x02
#define Speed_10Mhz			0x01

/************************** Function File ***************************/
void Reg_Out32(u32 addr,u32 data);
u32 Reg_In32(u32 addr);


#endif /* SRC_COMMON_H_ */
