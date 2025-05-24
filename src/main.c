/* =====================  main.c  ===================== */
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
#include "rtl8211fd_drv.h"

/* ————— IP 协议号硬编码 ————— */
#define PROTO_ICMP 1
#define PROTO_TCP   6
#define PROTO_UDP  17
/* ———————————————————— */

#include "lwip/etharp.h"    /* ETHTYPE_IP, ETHTYPE_ARP, SIZEOF_ETH_HDR */
#include "lwip/ip4.h"       /* struct ip_hdr, IPH_* */
#include "lwip/prot/udp.h"  /* struct udp_hdr */
#include "lwip/prot/tcp.h"  /* struct tcp_hdr */

#define IPERF_PORT      5001

#define IP_ADDR0        configIP_ADDR0
#define IP_ADDR1        configIP_ADDR1
#define IP_ADDR2        configIP_ADDR2
#define IP_ADDR3        configIP_ADDR3

#define NETMASK_ADDR0   255
#define NETMASK_ADDR1   255
#define NETMASK_ADDR2   255
#define NETMASK_ADDR3   0

#define GW_ADDR0        configIP_ADDR0
#define GW_ADDR1        configIP_ADDR1
#define GW_ADDR2        configIP_ADDR2
#define GW_ADDR3        1

ip4_addr_t ipaddr, netmask, gw;
struct netif gnetif;

/* 全局流统计变量，全部用 int 类型 */
static int flow_tot_pkts  = 0;
static int flow_tot_bytes = 0;
static int flow_src_pkts  = 0;
static int flow_dst_pkts  = 0;
static int flow_src_bytes = 0;

void crash(void);
void trap_entry(void);
void userInterrupt(void);

/* ---------- 时间基准 ---------- */
u32_t sys_jiffies(void) {
    u32 t = machineTimer_getTime(BSP_MACHINE_TIMER);
    return t / (SYSTEM_MACHINE_TIMER_HZ / 1000);
}
u32_t sys_now(void) {
    return sys_jiffies();
}

/* ---------- 封包 sniff + 过滤 ---------- */
static err_t sniff_input(struct pbuf *p, struct netif *netif) {
    const struct eth_hdr *eth = (const struct eth_hdr *)p->payload;
    u16_t etype = lwip_ntohs(eth->type);

    /* 1) ARP 直接放行 */
    if (etype == ETHTYPE_ARP) {
        bsp_printf("[PASS-ARP] len=%lu\r\n", (unsigned long)p->tot_len);
        return ethernet_input(p, netif);
    }

    /* 2) 非 IPv4 丢弃 */
    if (etype != ETHTYPE_IP || p->tot_len < SIZEOF_ETH_HDR + IP_HLEN) {
        bsp_printf("[DROP-ETH] eth=0x%04X tot_len=%lu\r\n",
                   etype, (unsigned long)p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }

    /* 3) 解析 IP */
    const struct ip_hdr *iph = (const struct ip_hdr *)((u8_t *)p->payload + SIZEOF_ETH_HDR);
    u8_t proto = IPH_PROTO(iph);
    u16_t ihl   = IPH_HL_BYTES(iph);

    /* 4) ICMP（Ping）放行 */
    if (proto == PROTO_ICMP) {
        bsp_printf("[PASS-ICMP] %d.%d.%d.%d → %d.%d.%d.%d len=%lu\r\n",
                   ip4_addr1(&iph->src), ip4_addr2(&iph->src),
                   ip4_addr3(&iph->src), ip4_addr4(&iph->src),
                   ip4_addr1(&iph->dest), ip4_addr2(&iph->dest),
                   ip4_addr3(&iph->dest), ip4_addr4(&iph->dest),
                   (unsigned long)p->tot_len);
        return ethernet_input(p, netif);
    }

    /* 5) 丢弃 mDNS */
    if (proto == PROTO_UDP) {
        const struct udp_hdr *udph = (const struct udp_hdr *)((u8_t *)iph + ihl);
        if (ip4_addr3(&iph->dest) == 224 &&
            ip4_addr4(&iph->dest) == 251 &&
            lwip_ntohs(udph->dest) == 5353) {
            bsp_printf("[DROP-mDNS] %d.%d.%d.%d:%u → 224.0.0.251:5353\r\n",
                       ip4_addr1(&iph->src), ip4_addr2(&iph->src),
                       ip4_addr3(&iph->src), ip4_addr4(&iph->src),
                       (unsigned)lwip_ntohs(udph->src));
            pbuf_free(p);
            return ERR_OK;
        }
    }

    /* 6) 只放行 IPERF_PORT（5001）的 TCP/UDP，其他丢弃 */
    u16_t sport = 0, dport = 0;
    if (proto == PROTO_TCP) {
        const struct tcp_hdr *tcph = (const struct tcp_hdr *)((u8_t *)iph + ihl);
        sport = lwip_ntohs(tcph->src);
        dport = lwip_ntohs(tcph->dest);
    } else if (proto == PROTO_UDP) {
        const struct udp_hdr *udph = (const struct udp_hdr *)((u8_t *)iph + ihl);
        sport = lwip_ntohs(udph->src);
        dport = lwip_ntohs(udph->dest);
    } else {
        bsp_printf("[DROP-NON-TCPUDP] proto=%u\r\n", proto);
        pbuf_free(p);
        return ERR_OK;
    }

    if (sport == IPERF_PORT || dport == IPERF_PORT) {
        /* 更新统计 */
        flow_tot_pkts++;
        flow_tot_bytes += (int)p->tot_len;
        if (dport == IPERF_PORT) {
            flow_src_pkts++;
            flow_src_bytes += (int)p->tot_len;
        } else {
            flow_dst_pkts++;
        }

        /* 打印 6 个特征 */
        bsp_printf("[FEATURE] "
                   "Sport=%d  "
                   "TotPkts=%d  "
                   "TotBytes=%d  "
                   "SrcPkts=%d  "
                   "DstPkts=%d  "
                   "SrcBytes=%d\r\n",
                   (int)sport,
                   flow_tot_pkts,
                   flow_tot_bytes,
                   flow_src_pkts,
                   flow_dst_pkts,
                   flow_src_bytes);

        return ethernet_input(p, netif);
    } else {
        bsp_printf("[DROP-PORT] %d.%d.%d.%d:%u → %d.%d.%d.%d:%u\r\n",
                   ip4_addr1(&iph->src), ip4_addr2(&iph->src),
                   ip4_addr3(&iph->src), ip4_addr4(&iph->src), (unsigned)sport,
                   ip4_addr1(&iph->dest), ip4_addr2(&iph->dest),
                   ip4_addr3(&iph->dest), ip4_addr4(&iph->dest), (unsigned)dport);
        pbuf_free(p);
        return ERR_OK;
    }
}

/* ---------- 初始化 LwIP & 网卡 ---------- */
void LwIP_Init(void) {
    IP4_ADDR(&ipaddr,   IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP4_ADDR(&netmask,  NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP4_ADDR(&gw,       GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);

    lwip_init();
    netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL,
              ethernetif_init, sniff_input);
    netif_set_default(&gnetif);
    if (netif_is_link_up(&gnetif)) netif_set_up(&gnetif);
    else                           netif_set_down(&gnetif);
}

/* ---------- 中断 & Handler ---------- */
void interrupt_init(void) {
    plic_set_threshold(BSP_PLIC, BSP_PLIC_CPU_0, 0);
    plic_set_priority(BSP_PLIC, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    plic_set_enable(BSP_PLIC, BSP_PLIC_CPU_0, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    csr_write(mtvec,    trap_entry);
    csr_set(mie,        MIE_MEIE);
    csr_write(mstatus,  MSTATUS_MPP | MSTATUS_MIE);
}

void trap(void) {
    int32_t mc = csr_read(mcause);
    if (mc < 0 && (mc & 0xF) == CAUSE_MACHINE_EXTERNAL) userInterrupt();
    else                                                crash();
}

void userInterrupt(void) {
    uint32_t claim;
    while ((claim = plic_claim(BSP_PLIC, BSP_PLIC_CPU_0))) {
        if (claim == SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT) {
            flush_data_cache();
            ethernetif_input(&gnetif);
        } else {
            crash();
        }
        plic_release(BSP_PLIC, BSP_PLIC_CPU_0, claim);
    }
}

void crash(void) {
    bsp_printf("\r\n*** CRASH ***\r\n");
    while (1) { }
}

/* ---------- PHY & MAC ---------- */
void clock_sel(int speed) {
    int v = (speed == Speed_1000Mhz) ? 0x03 : 0x00;
    write_u32(v, IO_APB_SLAVE_2_APB);
}

/* ---------- main ---------- */
int main(void) {
    int speed = Speed_1000Mhz, link_speed = 0, bLink = 0;

    MacRst(0,0);
    interrupt_init();
    dmasg_priority(DMASG_BASE, DMASG_CHANNEL0, 0,0);
    dmasg_priority(DMASG_BASE, DMASG_CHANNEL1, 0,0);

    bsp_printf("Phy Init...\r\n");
    rtl8211_drv_init();
    bsp_printf("Waiting Link Up...\r\n");
    speed = rtl8211_drv_linkup();
    if      (speed == Speed_1000Mhz) link_speed = 1000;
    else if (speed == Speed_100Mhz)  link_speed = 100;
    else if (speed == Speed_10Mhz)   link_speed = 10;
    bLink = 1;
    clock_sel(speed);
    MacNormalInit(speed);

    LwIP_Init();
    lwiperf_start_tcp_server(&ipaddr, IPERF_PORT, NULL, NULL);

    bsp_printf("iperf server Up\r\n");
    bsp_printf("IP: %d.%d.%d.%d   Mask: %d.%d.%d.%d   GW: %d.%d.%d.%d   Speed: %d Mbps\r\n",
               IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3,
               NETMASK_ADDR0,NETMASK_ADDR1,NETMASK_ADDR2,NETMASK_ADDR3,
               GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3,
               link_speed);

    for (;;) {
        if (check_dma_status(cur_des)) {
            ethernetif_input(&gnetif);
        } else {
            int st = rtl8211_drv_rddata(26);
            if (!(st & 0x04) && bLink) {
                bLink=0; bsp_printf("Disconnected\r\n");
            } else if ((st & 0x04) && !bLink) {
                speed = rtl8211_drv_linkup();
                clock_sel(speed);
                MacNormalInit(speed);
                bLink=1; bsp_printf("Connected\r\n");
            }
            sys_check_timeouts();
        }
    }
}
/* =====================  end of main.c  ===================== */
