/**
 * @file
 * Ethernet Interface Skeleton
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * This file is a skeleton for developing Ethernet network interface
 * drivers for lwIP. Add code to the low_level functions and do a
 * search-and-replace for the word "ethernetif" to replace it with
 * something that better describes your network interface.
 */

#include "lwip/opt.h"



#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "netif/ppp/pppoe.h"


#include "ethernetif.h"
#include "dmasg.h"
#include "common.h"
#include "reg.h"
#include "mac.h"

/* Define those to better describe your network interface. */
#define IFNAME0 'e'
#define IFNAME1 'n'

#define mem ((uint32_t*)0x80000)	//define out of 512KB heap memory size

#define LINK_SPEED_OF_YOUR_NETIF_IN_BPS 1000

//struct cmn_rx_ctrl 	rxctrl ={0};

volatile struct dmasg_descriptor descriptors0[FRAME_PACKET]  __attribute__ ((aligned (64)));

void flush_data_cache(){
    asm(".word(0x500F)");
}

void program_descriptor()
{

	for (int j=0; j<FRAME_PACKET; j++)
	{
		descriptors0[j].control = (u32)((BUFFER_SIZE)-1)  | 1 << 30;;
		descriptors0[j].from    = 0;
		descriptors0[j].to      = (u32)(mem + (j *(BUFFER_SIZE)) );
		descriptors0[j].next    = (u32) (descriptors0 + (j+1));
		descriptors0[j].status  = 0;
	}

	descriptors0[FRAME_PACKET-1].next = (u32) (descriptors0);	//last descriptors point to first descriptors

	dmasg_interrupt_pending_clear(DMASG_BASE,0,0xFFFFFFFF);
	dmasg_output_memory (DMASG_BASE, 0,  (u32)mem, 64);
	dmasg_input_stream(DMASG_BASE, 0, 0, 1, 1);
	dmasg_linked_list_start(DMASG_BASE, 0, (u32) descriptors0);

	cur_des=0;
}

/**
 * Helper struct to hold private data used to operate your ethernet interface.
 * Keeping the ethernet address of the MAC in this struct is not necessary
 * as it is alreadDMASG_CHANNEL_INTERRUPT_INPUT_PACKET_MASKy kept in the struct netif.
 * But this is only an example, anyway...
 */
struct ethernetif {
  struct eth_addr *ethaddr;
  /* Add whatever per-interface state that is needed here. */
};

/* Forward declarations. */
//static void  ethernetif_input(struct netif *netif);

/**
 * In this function, the hardware should be initialized.
 * Called from ethernetif_init().
 *
 * @param netif the already initialized lwip network interface structure
 *        for this ethernetif
 */
static void
low_level_init(struct netif *netif)
{
  struct ethernetif *ethernetif = netif->state;

  /* set MAC hardware address length */
  netif->hwaddr_len = ETHARP_HWADDR_LEN;

  /* set MAC hardware address */
  netif->hwaddr[0] = 0x00;
  netif->hwaddr[1] = 0x11;
  netif->hwaddr[2] = 0x22;
  netif->hwaddr[3] = 0x33;  
  netif->hwaddr[4] = 0x44;  
  netif->hwaddr[5] = 0x41;

  /* maximum transfer unit */
  netif->mtu = 1500;

  /* device capabilities */
  /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

#if LWIP_IPV6 && LWIP_IPV6_MLD
  /*
   * For hardware/netifs that implement MAC filtering.
   * All-nodes link-local is handled by default, so we must let the hardware know
   * to allow multicast packets in.
   * Should set mld_mac_filter previously. */
  if (netif->mld_mac_filter != NULL) {
    ip6_addr_t ip6_allnodes_ll;
    ip6_addr_set_allnodes_linklocal(&ip6_allnodes_ll);
    netif->mld_mac_filter(netif, &ip6_allnodes_ll, NETIF_ADD_MAC_FILTER);
  }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

  /* Do whatever else is needed to initialize interface. */
  program_descriptor();
}

/**
 * This function should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @param p the MAC packet to send (e.g. IP packet including MAC addresses and type)
 * @return ERR_OK if the packet could be sent
 *         an err_t value if the packet couldn't be sent
 *
 * @note Returning ERR_MEM here if a DMA queue of your MAC is full can lead to
 *       strange results. You might consider waiting for space in the DMA queue
 *       to become available since the stack doesn't retry to send a packet
 *       dropped because of memory failure (except for the TCP timers).
 */

static void SendData(uint32_t *pucEthernetBuffer,size_t xDataLength){

	int n;

  write_u32(xDataLength,IO_APB_SLAVE_2_APB+4);	//workaround for tkeep tlast handle with module tkeep_ctrl with abp3
  dmasg_input_memory(DMASG_BASE, 1, ((u32)pucEthernetBuffer), 64);
  dmasg_output_stream(DMASG_BASE, DMASG_CHANNEL1, 0, 0, 0, 1);
  dmasg_direct_start(DMASG_BASE, DMASG_CHANNEL1, xDataLength, 0);

  while(dmasg_busy(DMASG_BASE, DMASG_CHANNEL1));
}

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct ethernetif *ethernetif = netif->state;
  struct pbuf *q;

  //initiate transfer();

#if ETH_PAD_SIZE
  pbuf_remove_header(p, ETH_PAD_SIZE); /* drop the padding word */
#endif

  for (q = p; q != NULL; q = q->next) {
    /* Send the data from the pbuf to the interface, one pbuf at a
       time. The size of the data in each pbuf is kept in the ->len
       variable. */
//    send data from(q->payload, q->len);

      SendData(q->payload, q->len);
  }

//  signal that packet should be sent();

  MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
  if (((u8_t *)p->payload)[0] & 1) {
    /* broadcast or multicast packet*/
    MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
  } else {
    /* unicast packet */
    MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
  }
  /* increase ifoutdiscards or ifouterrors on error */

#if ETH_PAD_SIZE
  pbuf_add_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

  LINK_STATS_INC(link.xmit);

  return ERR_OK;
}

/**
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return a pbuf filled with the received packet (including MAC header)
 *         NULL on memory error
 */



/*
void dma_execution(uint8_t *pucEthernetBuffer,size_t xDataLength) {

    u32 poll_intr;
    u32 data;
    u32 buffer[1518];

	//transfer to DDR memory
	dmasg_output_memory (DMASG_BASE, DMASG_CHANNEL0, (u32)pucEthernetBuffer, 64);
	dmasg_input_stream(DMASG_BASE, DMASG_CHANNEL0, 0, 0, 0);
	dmasg_direct_start(DMASG_BASE, DMASG_CHANNEL0, xDataLength, 0);

	//enable ready signal to release data from tse
	rxctrl.rx_ready_rl = 1;
	rxctrl = control_rx(&rxctrl);

	while(dmasg_busy(DMASG_BASE, DMASG_CHANNEL0));

	flush_data_cache();

	//disable ready signal to block data from tse
	//disable mask to wait new incoming data
	rxctrl.rx_intr_mask = 0;
	rxctrl = control_rx(&rxctrl);
}

u32 ReceiveSize(void)
{
	u32 dmasg_len;

	rxctrl.rx_intr_mask = 1;
	rxctrl.rx_rd = 1;
	rxctrl = control_rx(&rxctrl);

	// return incoming traffic byte length
	dmasg_len = read_u32(IO_APB_SLAVE_0_APB+0x1C0);

	return dmasg_len;
}

void ReceiveData(uint8_t *pucEthernetBuffer , size_t xDataLength)
{
	dma_execution(pucEthernetBuffer,xDataLength);
}

 int Poll_Interrupt(void)
 {
 	//1 : interrupt , 0 : Normal
 	return read_u32(IO_APB_SLAVE_0_APB+0x1C4);
 }
*/
 int check_dma_status(int num_descriptor)
 {
	 if(descriptors0[num_descriptor].status & 0x3FFFFFFF)
		 return 1;
	 else
		 return 0;
 }

static struct pbuf *
low_level_input(struct netif *netif)
{
  struct ethernetif *ethernetif = netif->state;
  struct pbuf *p, *q;
  u16_t len;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  len =descriptors0[cur_des].status & DMASG_DESCRIPTOR_STATUS_BYTES;

#if ETH_PAD_SIZE
  len += ETH_PAD_SIZE; /* allow room for Ethernet padding */
#endif

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
  //p = pbuf_alloc_reference((mem+(cur_des*BUFFER_SIZE)), len, PBUF_REF);

  //bsp_printf("p addr = 0x%x pointer addr = 0x%x len = %d cur_des = %d\n\r",(u32)p,(u32)(mem+(cur_des*BUFFER_SIZE)),descriptors0[cur_des].status&DMASG_DESCRIPTOR_STATUS_BYTES,cur_des);

  descriptors0[cur_des].status = 0;

  if (p != NULL) {

#if ETH_PAD_SIZE
    pbuf_remove_header(p, ETH_PAD_SIZE); /* drop the padding word */
#endif

    /* We iterate over the pbuf chain until we have read the entire
     * packet into the pbuf. */
    for (q = p; q != NULL; q = q->next) {
      /* Read enough bytes to fill this pbuf in the chain. The
       * available data in the pbuf is given by the q->len
       * variable.
       * This does not necessarily have to be a memcpy, you can also preallocate
       * pbufs for a DMA-enabled MAC and after receiving truncate it to the
       * actually received size. In this case, ensure the tot_len member of the
       * pbuf is the sum of the chained pbuf len members.
       */
      //read data into(q->payload, q->len);
    	p->payload=(mem+(cur_des*BUFFER_SIZE));
    }
    //acknowledge that packet has been read();


    MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);
    if (((u8_t *)p->payload)[0] & 1) {
      /* broadcast or multicast packet*/
      MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
    } else {
      /* unicast packet*/
      MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
    }
#if ETH_PAD_SIZE
    pbuf_add_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

    LINK_STATS_INC(link.recv);
  } else {
   // drop packet();
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
  }
  cur_des=(cur_des+1) & ((unsigned int)FRAME_PACKET-1);

  return p;
}

/**
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface. Then the type of the received packet is determined and
 * the appropriate input function is called.
 *
 * @param netif the lwip network interface structure for this ethernetif
 */
void ethernetif_input(struct netif *netif)
{
  struct ethernetif *ethernetif;
  struct eth_hdr *ethhdr;
  struct pbuf *p;

  ethernetif = netif->state;

  /* move received packet into a new pbuf */
  p = low_level_input(netif);
  /* if no packet could be read, silently ignore this */
  if (p != NULL) {
    /* pass all packets to ethernet_input, which decides what packets it supports */
    if (netif->input(p, netif) != ERR_OK) {
      LWIP_DEBUGF(NETIF_DEBUG, ("ethernetif_input: IP input error\n"));
      pbuf_free(p);
      p = NULL;
    }
  }
}

/**
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 * This function should be passed as a parameter to netif_add().
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 *         any other err_t on error
 */
err_t ethernetif_init(struct netif *netif)
{
  struct ethernetif *ethernetif;

  LWIP_ASSERT("netif != NULL", (netif != NULL));

  ethernetif = mem_malloc(sizeof(struct ethernetif));
  if (ethernetif == NULL) {
    LWIP_DEBUGF(NETIF_DEBUG, ("ethernetif_init: out of memory\n"));
    return ERR_MEM;
  }

#if LWIP_NETIF_HOSTNAME
  /* Initialize interface hostname */
  netif->hostname = "lwip";
#endif /* LWIP_NETIF_HOSTNAME */

  /*
   * Initialize the snmp variables and counters inside the struct netif.
   * The last argument should be replaced with your link speed, in units
   * of bits per second.
   */
  MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, LINK_SPEED_OF_YOUR_NETIF_IN_BPS);

  netif->state = ethernetif;
  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  /* We directly use etharp_output() here to save a function call.
   * You can instead declare your own function an call etharp_output()
   * from it if you have to do some checks before sending (e.g. if link
   * is available...) */
#if LWIP_IPV4
  netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
  netif->linkoutput = low_level_output;

  ethernetif->ethaddr = (struct eth_addr *) & (netif->hwaddr[0]);

  /* initialize the hardware */
  low_level_init(netif);

  return ERR_OK;
}

