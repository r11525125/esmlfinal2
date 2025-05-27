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
#include "dmasg.h"
#include "common.h"
#include "reg.h"
#include "mac.h"
#include "riscv.h"
#include "plic.h"
#include "rtl8211fd_drv.h"    /* PHY 驅動 */

#include "lwip/etharp.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/tcp.h"

#include "packet_anomaly_detector.h"  /* 模型頭 */

/* —— Protocol numbers —— */
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP  17

/* —— Static IP configuration —— */
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

/* —— Per‐flow stats —— */
static uint32_t flow_tot_pkts  = 0;
static uint32_t flow_tot_bytes = 0;
static uint32_t flow_src_pkts  = 0;
static uint32_t flow_dst_pkts  = 0;
static uint32_t flow_src_bytes = 0;
static uint16_t last_sport     = 0;

/* —— ML推斷控制 —— */
static volatile int ml_enabled = 1;  // 可以動態開關ML推斷

/* —— External trap entry from trap.S —— */
extern void trap_entry(void);

/* —— Prototypes —— */
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
static void do_ml_inference(uint16_t sport);

/* —— Time base (for lwiperf) —— */
u32_t sys_jiffies(void) {
    u32 t = machineTimer_getTime(BSP_MACHINE_TIMER);
    return (t * 1000U) / SYSTEM_MACHINE_TIMER_HZ;
}

u32_t sys_now(void) {
    return sys_jiffies();
}

/* ========== ML推斷函數 ========== */
static void do_ml_inference(uint16_t sport) {
    if (!ml_enabled) return;

    float feats[6] = {
        (float)sport,
        (float)flow_tot_pkts,
        (float)flow_tot_bytes,
        (float)flow_src_pkts,
        (float)flow_dst_pkts,
        (float)flow_src_bytes
    };

    // 執行ML推斷
    packet_anomaly_detector_predict(feats, 6);

    // 重置統計（為下一個流做準備）
    flow_tot_pkts = flow_tot_bytes = 0;
    flow_src_pkts = flow_dst_pkts = flow_src_bytes = 0;
}

/* ========== 輕量級封包嗅探函數 ========== */
static err_t sniff_input(struct pbuf *p, struct netif *netif) {
    // 先做快速檢查，避免不必要的處理
    if (p->tot_len < SIZEOF_ETH_HDR + sizeof(struct ip_hdr)) {
        return ethernet_input(p, netif);
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)p->payload;
    u16_t etype = lwip_ntohs(eth->type);

    /* ARP 和非IP封包直接通過 */
    if (etype != ETHTYPE_IP) {
        return ethernet_input(p, netif);
    }

    /* 解析 IP 頭 */
    const struct ip_hdr *iph = (const struct ip_hdr *)((u8_t*)p->payload + SIZEOF_ETH_HDR);
    u8_t proto = IPH_PROTO(iph);
    u16_t ihl = IPH_HL_BYTES(iph);

    /* ICMP 直接通過 */
    if (proto == PROTO_ICMP) {
        return ethernet_input(p, netif);
    }

    /* 處理UDP - 過濾mDNS */
    if (proto == PROTO_UDP) {
        if (p->tot_len >= SIZEOF_ETH_HDR + ihl + sizeof(struct udp_hdr)) {
            const struct udp_hdr *udph = (const struct udp_hdr *)((u8_t*)iph + ihl);
            // 丟棄 mDNS (224.0.0.251:5353)
            if (ip4_addr3(&iph->dest) == 224 && ip4_addr4(&iph->dest) == 251 &&
                lwip_ntohs(udph->dest) == 5353) {
                pbuf_free(p);
                return ERR_OK;
            }
        }
        return ethernet_input(p, netif);
    }

    /* 處理TCP封包 */
    if (proto == PROTO_TCP && p->tot_len >= SIZEOF_ETH_HDR + ihl + sizeof(struct tcp_hdr)) {
        const struct tcp_hdr *tcph = (const struct tcp_hdr *)((u8_t*)iph + ihl);
        u16_t sport = lwip_ntohs(tcph->src);
        u16_t dport = lwip_ntohs(tcph->dest);

        /* 只跟踪 iperf 流量 */
        if (sport == IPERF_PORT || dport == IPERF_PORT) {
            /* 檢測新流（基於source port變化） */
            if (dport == IPERF_PORT && sport != last_sport) {
                // 如果之前有流在進行，先進行ML推斷
                if (last_sport != 0 && flow_tot_pkts > 0) {
                    do_ml_inference(last_sport);
                }

                // 重置統計為新流
                flow_tot_pkts = flow_tot_bytes = 0;
                flow_src_pkts = flow_dst_pkts = flow_src_bytes = 0;
                last_sport = sport;
            }

            /* 累加統計 */
            flow_tot_pkts++;
            flow_tot_bytes += p->tot_len;

            if (dport == IPERF_PORT) {
                flow_src_pkts++;
                flow_src_bytes += p->tot_len;
            } else {
                flow_dst_pkts++;
            }

            /* 檢查TCP標誌位 */
            u8_t flags = TCPH_FLAGS(tcph);

            /* 在FIN或RST時執行ML推斷 */
            if (flags & (TCP_FIN | TCP_RST)) {
                do_ml_inference(sport == IPERF_PORT ? sport : dport);
                last_sport = 0; // 清除當前流標記
            }
        }
    }

    /* 所有封包都正常通過lwIP處理 */
    return ethernet_input(p, netif);
}

/* ========== ICMP echo 回調 ========== */
static u8_t icmp_recv_cb(void *arg, struct raw_pcb *pcb,
                         struct pbuf *p, const ip_addr_t *addr)
{
    if (p->tot_len < sizeof(struct ip_hdr)) {
        pbuf_free(p);
        return 1;
    }

    struct ip_hdr *iph = (struct ip_hdr *)p->payload;
    u16_t ihl = IPH_HL(iph) * 4;

    if (p->tot_len < ihl + sizeof(struct icmp_echo_hdr)) {
        pbuf_free(p);
        return 1;
    }

    struct icmp_echo_hdr *ie = (struct icmp_echo_hdr *)((u8_t*)p->payload + ihl);

    if (ie->type == ICMP_ECHO) {
        ie->type = ICMP_ER;
        ie->chksum = 0;
        ie->chksum = inet_chksum(ie, p->tot_len - ihl);
        raw_sendto(icmp_pcb, p, addr);
    }

    pbuf_free(p);
    return 1;
}

/* ========== lwIP & netif 初始化 ========== */
static void LwIP_Init(void) {
    IP4_ADDR(&ipaddr,   IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP4_ADDR(&netmask,  NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP4_ADDR(&gw,       GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);

    lwip_init();

    // 使用自定義的sniff_input函數
    netif_add(&gnetif, &ipaddr, &netmask, &gw,
              NULL, ethernetif_init, sniff_input);

    netif_set_default(&gnetif);

    if (netif_is_link_up(&gnetif))
        netif_set_up(&gnetif);
    else
        netif_set_down(&gnetif);

    // 設置ICMP處理
    icmp_pcb = raw_new(IP_PROTO_ICMP);
    if (icmp_pcb != NULL) {
        raw_recv(icmp_pcb, icmp_recv_cb, NULL);
        raw_bind(icmp_pcb, IP_ADDR_ANY);
    }
}

/* ========== 中斷處理 - 保持原有邏輯 ========== */
void interrupt_init(void) {
    plic_set_threshold(BSP_PLIC, BSP_PLIC_CPU_0, 0);
    plic_set_priority(BSP_PLIC, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    plic_set_enable(BSP_PLIC, BSP_PLIC_CPU_0, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    csr_write(mtvec, trap_entry);
    csr_set(mie, MIE_MEIE);
    csr_write(mstatus, MSTATUS_MPP | MSTATUS_MIE);
}

void trap(void) {
    int32_t mcause = csr_read(mcause);
    int32_t interrupt = mcause < 0;
    int32_t cause = mcause & 0xF;

    if (interrupt) {
        switch (cause) {
        case CAUSE_MACHINE_EXTERNAL:
            userInterrupt();
            break;
        default:
            crash();
            break;
        }
    } else {
        crash();
    }
}

void userInterrupt(void) {
    uint32_t claim;

    // 處理所有pending中斷
    while ((claim = plic_claim(BSP_PLIC, BSP_PLIC_CPU_0))) {
        switch (claim) {
        case SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT:
            flush_data_cache();  // 重要：保持緩存一致性
            break;
        default:
            crash();
            break;
        }
        plic_release(BSP_PLIC, BSP_PLIC_CPU_0, claim);
    }
}

void crash(void) {
    bsp_printf("\n*** CRASH ***\n");
    while (1) { }
}

static void clock_sel(int speed) {
    int val = (speed == Speed_1000Mhz) ? 0x03 : 0x00;
    write_u32(val, IO_APB_SLAVE_2_APB);
}

/* ========== main函數 - 保持原有的輪詢邏輯 ========== */
int main(void) {
    int speed = Speed_1000Mhz, link_speed = 0;
    int check_connect, bLink = 0;

    // 硬件初始化
    MacRst(0, 0);
    interrupt_init();
    dmasg_priority(DMASG_BASE, DMASG_CHANNEL0, 0, 0);
    dmasg_priority(DMASG_BASE, DMASG_CHANNEL1, 0, 0);

    // PHY初始化
    bsp_printf("Phy Init...");
    rtl8211_drv_init();

    bsp_printf("Waiting Link Up...");
    speed = rtl8211_drv_linkup();

    if (speed == Speed_1000Mhz)      link_speed = 1000;
    else if (speed == Speed_100Mhz)  link_speed = 100;
    else if (speed == Speed_10Mhz)   link_speed = 10;
    else                             link_speed = 0;

    bLink = 1;
    clock_sel(speed);
    MacNormalInit(speed);

    // 網路協議棧初始化
    LwIP_Init();
    lwiperf_start_tcp_server(&ipaddr, IPERF_PORT, NULL, NULL);

    bsp_printf("iperf server Up\n\r");
    bsp_printf("=========================================\n\r");
    bsp_printf("======Lwip Raw Mode Iperf TCP Server ====\n\r");
    bsp_printf("======With ML Anomaly Detection==========\n\r");
    bsp_printf("=========================================\n\r");
    bsp_printf("======IP: \t\t%d.%d.%d.%d\n\r", IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    bsp_printf("======Netmask: \t\t%d.%d.%d.%d\n\r", NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    bsp_printf("======GateWay: \t\t%d.%d.%d.%d\n\r", GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);
    bsp_printf("======Link Speed: \t%d Mbps\n\r", link_speed);
    bsp_printf("======ML Detection: \t%s\n\r", ml_enabled ? "Enabled" : "Disabled");
    bsp_printf("=========================================\n\r");

    // 主循環 - 保持原有邏輯
    for (;;) {
        // 檢查DMA狀態，有封包就處理
        if (check_dma_status(cur_des)) {
            ethernetif_input(&gnetif);
        } else {
            // 檢查網路連接狀態
            check_connect = rtl8211_drv_rddata(26);

            if ((check_connect & 0x04) == 0 && bLink) {
                // 斷線
                bLink = 0;
                bsp_printf("Disconnected -- ");
            } else if ((check_connect & 0x04) && !bLink) {
                // 重新連線
                speed = rtl8211_drv_linkup();
                clock_sel(speed);
                MacNormalInit(speed);
                bLink = 1;
                bsp_printf("Connected -- ");
            }

            // 處理lwIP定時器
            sys_check_timeouts();
        }
    }

    return 0;
}

/* ===================== end of main.c ===================== */
