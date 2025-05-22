/*
 * commom.c
 *
 *  Created on: Aug 18, 2020
 *      Author: shchung
 */

#include <stdarg.h>
#include <stdint.h>

#include "bsp.h"

#include "common.h"


/************************** Function File ***************************/
void Reg_Out32(u32 addr,u32 data)
{
    write_u32(data,addr);
}

u32 Reg_In32(u32 addr)
{
    return read_u32(addr);
}
