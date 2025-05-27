/* ===================== main.c ===================== */
#include "lwip/init.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "netif/ethernet.h"
#include "ethernetif.h"
#include "lwiperf.h"
#include "bsp.h"
#include "dmasg.h"
#include "common.h"
#include "reg.h"
#include "mac.h"
#include "riscv.h"
#include "plic.h"
#include "rtl8211fd_drv.h"

#include "lwip/etharp.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/tcp.h"

#include <stdlib.h>  /* malloc, free */
#include "packet_anomaly_detector_old.h"

/* —— Protocol numbers —— */
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17

/* —— Static IP config —— */
#define IP_ADDR0       configIP_ADDR0
#define IP_ADDR1       configIP_ADDR1
#define IP_ADDR2       configIP_ADDR2
#define IP_ADDR3       configIP_ADDR3

#define NETMASK_ADDR0  255
#define NETMASK_ADDR1  255
#define NETMASK_ADDR2  255
#define NETMASK_ADDR3    0

#define GW_ADDR0       configIP_ADDR0
#define GW_ADDR1       configIP_ADDR1
#define GW_ADDR2       configIP_ADDR2
#define GW_ADDR3         1

#define IPERF_PORT     5001

/* —— Globals —— */
static ip4_addr_t   ipaddr, netmask, gw;
static struct netif gnetif;
static struct raw_pcb *icmp_pcb;

/* —— Per‐source‐port stats —— */
struct flow_stats {
    uint16_t sport;
    uint32_t tot_pkts;
    uint32_t tot_bytes;
    uint32_t src_pkts;
    uint32_t dst_pkts;
    uint32_t src_bytes;
    struct flow_stats *next;
};
static struct flow_stats *flow_head = NULL;

extern void trap_entry(void);

void      interrupt_init(void);
void      trap(void);
void      userInterrupt(void);
void      crash(void);
u32_t     sys_jiffies(void);
u32_t     sys_now(void);
static err_t sniff_input(struct pbuf *p, struct netif *netif);
static u8_t icmp_recv_cb(void *arg, struct raw_pcb *pcb,
                         struct pbuf *p, const ip_addr_t *addr);
static void LwIP_Init(void);
static void clock_sel(int speed);

/* every 5s clear all stats */
static void reset_flow_stats(void *arg) {
    struct flow_stats *f = flow_head;
    while (f) {
        struct flow_stats *n = f->next;
        free(f);
        f = n;
    }
    flow_head = NULL;
    sys_timeout(5000, reset_flow_stats, NULL);
}

u32_t sys_jiffies(void) {
    u32 t = machineTimer_getTime(BSP_MACHINE_TIMER);
    return (t * 1000U) / SYSTEM_MACHINE_TIMER_HZ;
}
u32_t sys_now(void) { return sys_jiffies(); }

static err_t sniff_input(struct pbuf *p, struct netif *netif) {
    const struct eth_hdr *eth = (const struct eth_hdr *)p->payload;
    u16_t etype = lwip_ntohs(eth->type);
    if (etype == ETHTYPE_ARP ||
        etype != ETHTYPE_IP ||
        p->tot_len < SIZEOF_ETH_HDR + sizeof(struct ip_hdr)) {
        err_t r = ethernet_input(p, netif);
        sys_check_timeouts();
        return r;
    }

    const struct ip_hdr *iph = (const struct ip_hdr *)((u8_t*)p->payload + SIZEOF_ETH_HDR);
    u8_t proto = IPH_PROTO(iph);
    u16_t ihl   = IPH_HL_BYTES(iph);

    /* ICMP: pass through, handled by raw PCB */
    if (proto == PROTO_ICMP) {
        err_t r = ethernet_input(p, netif);
        sys_check_timeouts();
        return r;
    }

    /* drop mDNS */
    if (proto == PROTO_UDP) {
        const struct udp_hdr *udph = (const struct udp_hdr *)((u8_t*)iph + ihl);
        if (ip4_addr3(&iph->dest)==224 && ip4_addr4(&iph->dest)==251 &&
            lwip_ntohs(udph->dest)==5353) {
            pbuf_free(p);
            sys_check_timeouts();
            return ERR_OK;
        }
    }

    /* extract ports */
    u16_t sport=0, dport=0;
    if (proto==PROTO_TCP) {
        const struct tcp_hdr *tcph = (const struct tcp_hdr *)((u8_t*)iph + ihl);
        sport = lwip_ntohs(tcph->src);
        dport = lwip_ntohs(tcph->dest);
    } else {
        const struct udp_hdr *udph = (const struct udp_hdr *)((u8_t*)iph + ihl);
        sport = lwip_ntohs(udph->src);
        dport = lwip_ntohs(udph->dest);
    }

    /* only IPERF_PORT */
    if (sport==IPERF_PORT || dport==IPERF_PORT) {
        /* find or alloc stats */
        struct flow_stats **pp = &flow_head;
        while (*pp && (*pp)->sport!=sport) pp=&(*pp)->next;
        if (!*pp) {
            *pp = malloc(sizeof(**pp));
            if (*pp) {
                (*pp)->sport     = sport;
                (*pp)->tot_pkts  = 0;
                (*pp)->tot_bytes = 0;
                (*pp)->src_pkts  = 0;
                (*pp)->dst_pkts  = 0;
                (*pp)->src_bytes = 0;
                (*pp)->next      = NULL;
            }
        }
        struct flow_stats *f = *pp;
        if (f) {
            if (proto==PROTO_TCP) {
                const struct tcp_hdr *tcph = (const struct tcp_hdr *)((u8_t*)iph + ihl);
                u8_t flags = TCPH_FLAGS(tcph);
                /* only count PSH data packets */
                if (flags & TCP_PSH) {
                    f->tot_pkts++;
                    f->tot_bytes  += p->tot_len;
                    if (dport==IPERF_PORT) {
                        f->src_pkts++;
                        f->src_bytes += p->tot_len;
                    } else {
                        f->dst_pkts++;
                    }
                }
                /* on FIN/RST, print and free only if data seen */
                if ((flags&TCP_FIN)||(flags&TCP_RST)) {
                    if (f->tot_pkts > 0) {
                        bsp_printf(
                          "[ANOMALY] Sport=%d TotPkts=%d TotBytes=%d "
                          "SrcPkts=%d DstPkts=%d SrcBytes=%d\r\n",
                          f->sport,
                          (int)f->tot_pkts,
                          (int)f->tot_bytes,
                          (int)f->src_pkts,
                          (int)f->dst_pkts,
                          (int)f->src_bytes
                        );
                    }
                    *pp = f->next;
                    free(f);
                }
            } else {
                /* UDP: unchanged logic */
                f->tot_pkts++;
                f->tot_bytes  += p->tot_len;
                if (dport==IPERF_PORT) {
                    f->src_pkts++;
                    f->src_bytes += p->tot_len;
                } else {
                    f->dst_pkts++;
                }
                /* only print if anomaly and skip score */
                float score = packet_anomaly_detector_predict((float[]){
                    (float)f->sport, (float)f->tot_pkts, (float)f->tot_bytes,
                    (float)f->src_pkts, (float)f->dst_pkts, (float)f->src_bytes
                }, 6);
                if (score > 50.0f) {
                    bsp_printf(
                      "[ANOMALY] Sport=%d TotPkts=%d TotBytes=%d "
                      "SrcPkts=%d DstPkts=%d SrcBytes=%d\r\n",
                      f->sport, (int)f->tot_pkts, (int)f->tot_bytes,
                      (int)f->src_pkts, (int)f->dst_pkts, (int)f->src_bytes
                    );
                }
            }
        }
    }

    err_t ret = ethernet_input(p, netif);
    sys_check_timeouts();
    return ret;
}

/* ICMP echo callback */
static u8_t icmp_recv_cb(void *arg, struct raw_pcb *pcb,
                         struct pbuf *p, const ip_addr_t *addr)
{
    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    struct icmp_echo_hdr *ie = (struct icmp_echo_hdr *)
        ((u8_t*)p->payload + (IPH_HL(iph)*4));
    if (ie->type==ICMP_ECHO) {
        ie->type = ICMP_ER;
        ie->chksum=0;
        ie->chksum=inet_chksum(ie,p->tot_len-(IPH_HL(iph)*4));
        raw_sendto(icmp_pcb,p,addr);
    }
    pbuf_free(p);
    return 1;
}

static void LwIP_Init(void) {
    IP4_ADDR(&ipaddr,IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3);
    IP4_ADDR(&netmask,NETMASK_ADDR0,NETMASK_ADDR1,NETMASK_ADDR2,NETMASK_ADDR3);
    IP4_ADDR(&gw,GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3);

    lwip_init();
    netif_add(&gnetif,&ipaddr,&netmask,&gw,NULL,ethernetif_init,sniff_input);
    netif_set_default(&gnetif);
    if(netif_is_link_up(&gnetif)) netif_set_up(&gnetif);
    else                           netif_set_down(&gnetif);

    icmp_pcb = raw_new(IP_PROTO_ICMP);
    raw_recv(icmp_pcb,icmp_recv_cb,NULL);
    raw_bind(icmp_pcb,IP_ADDR_ANY);

    sys_timeout(5000,reset_flow_stats,NULL);
}

void interrupt_init(void) {
    plic_set_threshold(BSP_PLIC,BSP_PLIC_CPU_0,0);
    plic_set_priority(BSP_PLIC,SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT,1);
    plic_set_enable(BSP_PLIC,BSP_PLIC_CPU_0,SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT,1);
    csr_write(mtvec,trap_entry);
    csr_set(mie,MIE_MEIE);
    csr_write(mstatus,MSTATUS_MPP|MSTATUS_MIE);
}

void trap(void) {
    int32_t mc=csr_read(mcause);
    if(mc<0&&(mc&0xF)==CAUSE_MACHINE_EXTERNAL) userInterrupt();
    else crash();
}

void userInterrupt(void) {
    flush_data_cache();
    uint32_t claim;
    while((claim=plic_claim(BSP_PLIC,BSP_PLIC_CPU_0))) {
        if(claim==SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT) {
            ethernetif_input(&gnetif);
            sys_check_timeouts();
        } else crash();
        plic_release(BSP_PLIC,BSP_PLIC_CPU_0,claim);
    }
}

void crash(void) {
    bsp_printf("\n*** CRASH ***\n");
    while(1){}
}

static void clock_sel(int speed) {
    int v=(speed==Speed_1000Mhz)?0x03:0x00;
    write_u32(v,IO_APB_SLAVE_2_APB);
}

int main(void) {
    int speed=Speed_1000Mhz, link_speed=0;
    MacRst(0,0);
    interrupt_init();
    dmasg_priority(DMASG_BASE,DMASG_CHANNEL0,0,0);
    dmasg_priority(DMASG_BASE,DMASG_CHANNEL1,0,0);

    bsp_printf("Phy Init...\r\n");
    rtl8211_drv_init();
    bsp_printf("Waiting Link Up...\r\n");
    speed=rtl8211_drv_linkup();
    if(speed==Speed_1000Mhz) link_speed=1000;
    else if(speed==Speed_100Mhz) link_speed=100;
    else if(speed==Speed_10Mhz) link_speed=10;
    clock_sel(speed);
    MacNormalInit(speed);

    LwIP_Init();
    lwiperf_start_tcp_server(&ipaddr,IPERF_PORT,NULL,NULL);

    bsp_printf("iperf up: IP=%d.%d.%d.%d MASK=%d.%d.%d.%d GW=%d.%d.%d.%d SPEED=%dMbps\r\n",
               IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3,
               NETMASK_ADDR0,NETMASK_ADDR1,NETMASK_ADDR2,NETMASK_ADDR3,
               GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3,
               link_speed);

    for(;;) {
        if(check_dma_status(cur_des)) {
            ethernetif_input(&gnetif);
            sys_check_timeouts();
        } else {
            int st=rtl8211_drv_rddata(26);
            static int bLink=1;
            if(!(st&0x04)&&bLink) {
                bLink=0; bsp_printf("Disconnected\r\n");
            } else if((st&0x04)&&!bLink) {
                speed=rtl8211_drv_linkup();
                clock_sel(speed);
                MacNormalInit(speed);
                bLink=1; bsp_printf("Connected\r\n");
            }
            sys_check_timeouts();
        }
    }
    return 0;
}
/* ===================== end of main.c ===================== */
