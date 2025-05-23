#include "lwip/init.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"
#include "ethernetif.h"
#include "bsp.h"
#include "dmasg.h"
#include "common.h"
#include "reg.h"
#include "mac.h"
#include "riscv.h"
#include "plic.h"
#include "lwiperf.h"
#include "compatibility.h"
#include "mac.h"
#include "rtl8211fd_drv.h"

/*Static IP ADDRESS: IP_ADDR0.IP_ADDR1.IP_ADDR2.IP_ADDR3 */
 #define IP_ADDR0                    configIP_ADDR0
 #define IP_ADDR1                    configIP_ADDR1
 #define IP_ADDR2                    configIP_ADDR2
 #define IP_ADDR3                    configIP_ADDR3

 /*NETMASK*/
 #define NETMASK_ADDR0               255
 #define NETMASK_ADDR1               255
 #define NETMASK_ADDR2               255
 #define NETMASK_ADDR3                 0

 /*Gateway Address*/
 #define GW_ADDR0                    configIP_ADDR0
 #define GW_ADDR1                    configIP_ADDR1
 #define GW_ADDR2                    configIP_ADDR2
 #define GW_ADDR3                    1
 /* USER CODE END 0 */
 //struct cmn_rx_ctrl 	_rxctrl ={0};

 ip4_addr_t ipaddr;
 ip4_addr_t netmask;
 ip4_addr_t gw;
 ip4_addr_t client_addr;

struct netif gnetif;
void crash();
void trap_entry();
void userInterrupt();
int incoming_packet=0;


u32_t sys_jiffies(void)
{
	u32 get_time;

	get_time = machineTimer_getTime(BSP_MACHINE_TIMER);

    return ((get_time)/(SYSTEM_MACHINE_TIMER_HZ/1000));
}

/*
 * Returns the current time in milliseconds.
 */
u32_t sys_now(void)
{
	u32 get_time;

	get_time = machineTimer_getTime(BSP_MACHINE_TIMER);

	return ((get_time)/(SYSTEM_MACHINE_TIMER_HZ/1000));

}


 void LwIP_Init(void)
 {

     IP4_ADDR(&ipaddr,IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3);
     IP4_ADDR(&netmask,NETMASK_ADDR0,NETMASK_ADDR1,NETMASK_ADDR2,NETMASK_ADDR3);
     IP4_ADDR(&gw,GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3);
     //IP4_ADDR(&client_addr,192,168,31,123);

     /* Initilialize the LwIP stack without RTOS */
     lwip_init();

     /* add the network interface (IPv4/IPv6) without RTOS */
     netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL,
               &ethernetif_init, &ethernet_input);

     /* Registers the default network interface */
     netif_set_default(&gnetif);

     if (netif_is_link_up(&gnetif))
     {
      /*When the netif is fully configured this function must be called */
         netif_set_up(&gnetif);
     }
     else
     {
         /* When the netif link is down this function must be called */
         netif_set_down(&gnetif);
     }

 }


 void interrupt_init(){

 	plic_set_threshold(BSP_PLIC, BSP_PLIC_CPU_0, 0);
 	plic_set_priority(BSP_PLIC, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
 	plic_set_enable(BSP_PLIC, BSP_PLIC_CPU_0, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
 	csr_write(mtvec, trap_entry);
    csr_set(mie, MIE_MEIE);
 	csr_write(mstatus, MSTATUS_MPP | MSTATUS_MIE);
 }

void trap(){
	int32_t mcause = csr_read(mcause);
	int32_t interrupt = mcause < 0;
	int32_t cause     = mcause & 0xF;
	if(interrupt){
		switch(cause){
		case CAUSE_MACHINE_EXTERNAL: userInterrupt(); break;
		default: crash(); break;
		}
	} else {
		crash();
	}
}

void userInterrupt(){
	uint32_t claim;
	//While there is pending interrupts
	while(claim = plic_claim(BSP_PLIC, BSP_PLIC_CPU_0)){
		switch(claim){
		case SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT:
				flush_data_cache();
			break;
			default: crash(); break;
		}
		plic_release(BSP_PLIC, BSP_PLIC_CPU_0, claim);
	}
}
void crash(){
	bsp_printf("\n*** CRASH ***\n");
	while(1);
}

void clock_sel(int speed)
{
	int val=0;

	if(speed == Speed_1000Mhz)	val=0x03;
	else						val=0x00;

	write_u32(val,IO_APB_SLAVE_2_APB);
}



int main(void)
 {
	int state;
	int n,speed=Speed_1000Mhz,link_speed=0;
	int check_connect;
	int bLink=0;


	MacRst(0,0);
	//_rxctrl.rx_intr_mask = 1;
	//control_rx(&_rxctrl);

	interrupt_init();

    dmasg_priority(DMASG_BASE, DMASG_CHANNEL0, 0,0);
	dmasg_priority(DMASG_BASE, DMASG_CHANNEL1, 0,0);

	bsp_printf("Phy Init...");

	rtl8211_drv_init();
	bsp_printf("Waiting Link Up...");
	speed=rtl8211_drv_linkup();

	if(speed == Speed_1000Mhz)		link_speed = 1000;
	else if(speed == Speed_100Mhz)	link_speed = 100;
	else if(speed == Speed_10Mhz)	link_speed = 10;
	else							link_speed = 0;

	bLink =1;
	clock_sel(speed);

	MacNormalInit(speed);

	LwIP_Init();

	lwiperf_start_tcp_server( &ipaddr, 5001, NULL, NULL );

	bsp_printf("iperf server Up\n\r");

	bsp_printf("=========================================\n\r");
	bsp_printf("======Lwip Raw Mode Iperf TCP Server ====\n\r");
	bsp_printf("=========================================\n\r");
	bsp_printf("======IP: \t\t%d.%d.%d.%d\n\r",IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3);
	bsp_printf("======Netmask: \t\t%d.%d.%d.%d\n\r",NETMASK_ADDR0,NETMASK_ADDR1,NETMASK_ADDR2,NETMASK_ADDR3);
	bsp_printf("======GateWay: \t\t%d.%d.%d.%d\n\r",GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3);
	bsp_printf("======link Speed: \t%d Mbps\n\r",link_speed);
	bsp_printf("=========================================\n\r");

	for(;;)
	{

		if(check_dma_status(cur_des))
		{
			ethernetif_input(&gnetif);	//get ethernet input packet event
		}
		else
		{
			check_connect=rtl8211_drv_rddata(26);

			if((check_connect & 0x04) == 0 && (bLink))
			{
				bLink=0;
				bsp_printf("Disconnected -- ");
			}
			else if((check_connect & 0x04) && (!bLink))
			{
				speed=rtl8211_drv_linkup();
				clock_sel(speed);
				MacNormalInit(speed);
				bLink=1;
				bsp_printf("Connected -- ");
			}
			sys_check_timeouts();
		}
	}
}
