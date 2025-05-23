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
#include "mac.h"
#include "rtl8211fd_drv.h"

/* --- NEW: 解析封包所需表頭 ------------------------------------ */
#include "lwip/etharp.h"       /* ETHTYPE_IP, SIZEOF_ETH_HDR, struct eth_hdr */
#include "lwip/ip4.h"          /* struct ip_hdr, IPH_* */
#include "lwip/udp.h"          /* IP_PROTO_UDP */
#include "lwip/tcp.h"          /* IP_PROTO_TCP */
#include "lwip/prot/udp.h"     /* struct udp_hdr */
#include "lwip/prot/tcp.h"     /* struct tcp_hdr */
/* --------------------------------------------------------------- */

/* Static IP ADDRESS: IP_ADDR0.IP_ADDR1.IP_ADDR2.IP_ADDR3 */
#define IP_ADDR0   configIP_ADDR0
#define IP_ADDR1   configIP_ADDR1
#define IP_ADDR2   configIP_ADDR2
#define IP_ADDR3   configIP_ADDR3

/* NETMASK */
#define NETMASK_ADDR0   255
#define NETMASK_ADDR1   255
#define NETMASK_ADDR2   255
#define NETMASK_ADDR3     0

/* Gateway Address */
#define GW_ADDR0   configIP_ADDR0
#define GW_ADDR1   configIP_ADDR1
#define GW_ADDR2   configIP_ADDR2
#define GW_ADDR3     1

ip4_addr_t ipaddr;
ip4_addr_t netmask;
ip4_addr_t gw;
ip4_addr_t client_addr;

struct netif gnetif;
void crash(void);
void trap_entry(void);
void userInterrupt(void);

/* ---------- 時間基準 ---------- */
u32_t sys_jiffies(void)
{
    u32 t = machineTimer_getTime(BSP_MACHINE_TIMER);
    return t / (SYSTEM_MACHINE_TIMER_HZ / 1000);
}

u32_t sys_now(void)
{
    return sys_jiffies();
}

/* ---------- NEW: 封包 sniff hook ---------- */
static err_t sniff_input(struct pbuf *p, struct netif *netif)
{
    const struct eth_hdr *eth = (const struct eth_hdr *)p->payload;

    bsp_printf("\r\n[PKT] len=%u  "
               "%02X:%02X:%02X:%02X:%02X:%02X -> "
               "%02X:%02X:%02X:%02X:%02X:%02X  etype=0x%04X",
               p->tot_len,
               eth->src.addr[0], eth->src.addr[1], eth->src.addr[2],
               eth->src.addr[3], eth->src.addr[4], eth->src.addr[5],
               eth->dest.addr[0], eth->dest.addr[1], eth->dest.addr[2],
               eth->dest.addr[3], eth->dest.addr[4], eth->dest.addr[5],
               lwip_htons(eth->type));

    /* IPv4 進一步解析 */
    if (eth->type == PP_HTONS(ETHTYPE_IP) && p->len >= (SIZEOF_ETH_HDR + IP_HLEN))
    {
        const struct ip_hdr *iph = (const struct ip_hdr *)((u8_t *)p->payload + SIZEOF_ETH_HDR);
        u8_t proto      = IPH_PROTO(iph);
        u16_t ihl_bytes = IPH_HL_BYTES(iph);

        bsp_printf("  IP %d.%d.%d.%d -> %d.%d.%d.%d  proto=%u",
                   ip4_addr1(&iph->src), ip4_addr2(&iph->src),
                   ip4_addr3(&iph->src), ip4_addr4(&iph->src),
                   ip4_addr1(&iph->dest), ip4_addr2(&iph->dest),
                   ip4_addr3(&iph->dest), ip4_addr4(&iph->dest),
                   proto);

        if (proto == IP_PROTO_UDP && p->len >= SIZEOF_ETH_HDR + ihl_bytes + sizeof(struct udp_hdr))
        {
            const struct udp_hdr *udph = (const struct udp_hdr *)((u8_t *)iph + ihl_bytes);
            bsp_printf("  UDP src=%u dst=%u",
                       lwip_htons(udph->src), lwip_htons(udph->dest));
        }
        else if (proto == IP_PROTO_TCP && p->len >= SIZEOF_ETH_HDR + ihl_bytes + sizeof(struct tcp_hdr))
        {
            const struct tcp_hdr *tcph = (const struct tcp_hdr *)((u8_t *)iph + ihl_bytes);
            bsp_printf("  TCP src=%u dst=%u",
                       lwip_htons(tcph->src), lwip_htons(tcph->dest));
        }
    }

    /* 繼續交回 lwIP 標準處理 */
    return ethernet_input(p, netif);
}

/* ---------- LwIP + 網卡 初始化 ---------- */
void LwIP_Init(void)
{
    IP4_ADDR(&ipaddr,   IP_ADDR0,   IP_ADDR1,   IP_ADDR2,   IP_ADDR3);
    IP4_ADDR(&netmask,  NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP4_ADDR(&gw,       GW_ADDR0,   GW_ADDR1,   GW_ADDR2,   GW_ADDR3);

    lwip_init();

    /* 用 sniff_input 取代 ethernet_input */
    netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL,
              ethernetif_init, sniff_input);
    netif_set_default(&gnetif);

    if (netif_is_link_up(&gnetif))
        netif_set_up(&gnetif);
    else
        netif_set_down(&gnetif);
}

/* ---------- 中斷設定 & Handler ---------- */
void interrupt_init(void)
{
    plic_set_threshold(BSP_PLIC, BSP_PLIC_CPU_0, 0);
    plic_set_priority(BSP_PLIC, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    plic_set_enable(BSP_PLIC, BSP_PLIC_CPU_0, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    csr_write(mtvec, trap_entry);
    csr_set(mie, MIE_MEIE);
    csr_write(mstatus, MSTATUS_MPP | MSTATUS_MIE);
}

void trap(void)
{
    int32_t mc = csr_read(mcause);
    if (mc < 0 && (mc & 0xF) == CAUSE_MACHINE_EXTERNAL)
        userInterrupt();
    else
        crash();
}

void userInterrupt(void)
{
    uint32_t claim;
    while ((claim = plic_claim(BSP_PLIC, BSP_PLIC_CPU_0)))
    {
        if (claim == SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT)
            flush_data_cache();
        else
            crash();
        plic_release(BSP_PLIC, BSP_PLIC_CPU_0, claim);
    }
}

void crash(void)
{
    bsp_printf("\n*** CRASH ***\n");
    while (1) { }
}

/* ---------- PHY & MAC 設定 ---------- */
void clock_sel(int speed)
{
    int v = (speed == Speed_1000Mhz) ? 0x03 : 0x00;
    write_u32(v, IO_APB_SLAVE_2_APB);
}

/* ---------- main ---------- */
int main(void)
{
    int speed = Speed_1000Mhz, link_speed = 0;
    int bLink = 0;

    MacRst(0, 0);
    interrupt_init();

    dmasg_priority(DMASG_BASE, DMASG_CHANNEL0, 0, 0);
    dmasg_priority(DMASG_BASE, DMASG_CHANNEL1, 0, 0);

    bsp_printf("Phy Init...");
    rtl8211_drv_init();
    bsp_printf("Waiting Link Up...");
    speed = rtl8211_drv_linkup();

    if      (speed == Speed_1000Mhz) link_speed = 1000;
    else if (speed == Speed_100Mhz)  link_speed = 100;
    else if (speed == Speed_10Mhz)   link_speed = 10;

    bLink = 1;
    clock_sel(speed);
    MacNormalInit(speed);

    LwIP_Init();
    lwiperf_start_tcp_server(&ipaddr, 5001, NULL, NULL);

    bsp_printf("iperf server Up\n\r");
    bsp_printf("=========================================\n\r");
    bsp_printf("======Lwip Raw Mode Iperf TCP Server ====\n\r");
    bsp_printf("=========================================\n\r");
    bsp_printf("IP:       %d.%d.%d.%d\n\r", IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    bsp_printf("Netmask:  %d.%d.%d.%d\n\r", NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    bsp_printf("GateWay:  %d.%d.%d.%d\n\r", GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
    bsp_printf("link Speed: %d Mbps\n\r", link_speed);
    bsp_printf("=========================================\n\r");

    for (;;)
    {
        if (check_dma_status(cur_des))
        {
            ethernetif_input(&gnetif);
        }
        else
        {
            int st = rtl8211_drv_rddata(26);
            if (!(st & 0x04) && bLink)
            {
                bLink = 0;
                bsp_printf("Disconnected -- ");
            }
            else if ((st & 0x04) && !bLink)
            {
                speed = rtl8211_drv_linkup();
                clock_sel(speed);
                MacNormalInit(speed);
                bLink = 1;
                bsp_printf("Connected -- ");
            }
            sys_check_timeouts();
        }
    }
}
/* =====================  end of main.c  ===================== */
