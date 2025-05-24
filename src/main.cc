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

// TinyML (TensorFlow Lite Micro)
#include "tensorflow/lite/micro/all_ops_resolver.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_error_reporter.h"
#include "tensorflow/lite/schema/schema_generated.h"

// Your model data (generated from iforest_scada.tflite)
#include "model/iforest_scada_model_data.h"

// ————— IP 协议号硬编码 —————
#define PROTO_ICMP 1
#define PROTO_TCP   6
#define PROTO_UDP  17
// ————————————————————

#include "lwip/etharp.h"    /* ETHTYPE_IP, ETHTYPE_ARP, SIZEOF_ETH_HDR */
#include "lwip/ip4.h"       /* struct ip_hdr, IPH_* */
#include "lwip/prot/udp.h"  /* struct udp_hdr */
#include "lwip/prot/tcp.h"  /* struct tcp_hdr */

#define IP_ADDR0   configIP_ADDR0
#define IP_ADDR1   configIP_ADDR1
#define IP_ADDR2   configIP_ADDR2
#define IP_ADDR3   configIP_ADDR3

#define NETMASK_ADDR0   255
#define NETMASK_ADDR1   255
#define NETMASK_ADDR2   255
#define NETMASK_ADDR3     0

#define GW_ADDR0   configIP_ADDR0
#define GW_ADDR1   configIP_ADDR1
#define GW_ADDR2   configIP_ADDR2
#define GW_ADDR3     1

/* ---------- 全局变量 ---------- */
static struct netif gnetif;

/* ---------- 时间基准 ---------- */
u32_t sys_jiffies(void) {
    u32 t = machineTimer_getTime(BSP_MACHINE_TIMER);
    return t / (SYSTEM_MACHINE_TIMER_HZ / 1000);
}
u32_t sys_now(void) {
    return sys_jiffies();
}

/* ---------- TinyML 配置 ---------- */
constexpr int kTensorArenaSize = 64 * 1024;
static uint8_t tensor_arena[kTensorArenaSize];

static tflite::ErrorReporter* error_reporter = nullptr;
static const tflite::Model* model = nullptr;
static tflite::MicroInterpreter* interpreter = nullptr;
static TfLiteTensor* model_input = nullptr;
static TfLiteTensor* model_output = nullptr;
static bool ml_initialized = false;

// 特征维度（与训练时一致）
#define FEATURE_DIM 4

static void TinyML_Init() {
    static tflite::MicroErrorReporter micro_error_reporter;
    error_reporter = &micro_error_reporter;

    model = tflite::GetModel(iforest_scada_tflite);
    if (model->version() != TFLITE_SCHEMA_VERSION) {
        MicroPrintf("Model schema mismatch\n\r");
        while (1);
    }

    static tflite::AllOpsResolver resolver;
    static tflite::MicroInterpreter static_interpreter(
        model, resolver, tensor_arena, kTensorArenaSize, error_reporter);
    interpreter = &static_interpreter;

    if (interpreter->AllocateTensors() != kTfLiteOk) {
        MicroPrintf("AllocateTensors() failed\n\r");
        while (1);
    }

    model_input  = interpreter->input(0);
    model_output = interpreter->output(0);
    ml_initialized = true;
}

/* ---------- 抓包 + TinyML 推理钩子 ---------- */
static err_t sniff_input(struct pbuf *p, struct netif *netif) {
    if (!ml_initialized) {
        TinyML_Init();
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)p->payload;
    u16_t etype = lwip_ntohs(eth->type);

    // 只处理 IPv4
    if (etype != ETHTYPE_IP || p->tot_len < SIZEOF_ETH_HDR + IP_HLEN) {
        pbuf_free(p);
        return ERR_OK;
    }

    const struct ip_hdr *iph = (const struct ip_hdr *)((u8_t*)p->payload + SIZEOF_ETH_HDR);
    u8_t proto = IPH_PROTO(iph);
    u16_t ihl   = IPH_HL_BYTES(iph);

    u16_t sport = 0, dport = 0;
    if (proto == PROTO_TCP) {
        const struct tcp_hdr* tcph = (const struct tcp_hdr*)((u8_t*)iph + ihl);
        sport = lwip_ntohs(tcph->src);
        dport = lwip_ntohs(tcph->dest);
    } else if (proto == PROTO_UDP) {
        const struct udp_hdr* udph = (const struct udp_hdr*)((u8_t*)iph + ihl);
        sport = lwip_ntohs(udph->src);
        dport = lwip_ntohs(udph->dest);
    }

    // 构造浮点特征向量：{总长度, 协议号, 源端口, 目的端口}
    float features[FEATURE_DIM] = {
        (float)p->tot_len,
        (float)proto,
        (float)sport,
        (float)dport
    };

    // 量化输入到 int8
    float in_scale  = model_input->params.scale;
    int   in_zp     = model_input->params.zero_point;
    for (int i = 0; i < FEATURE_DIM; ++i) {
        int32_t q = (int32_t)(features[i] / in_scale + in_zp);
        if (q < -128) q = -128;
        if (q > 127)  q = 127;
        model_input->data.int8[i] = static_cast<int8_t>(q);
    }

    // 执行推理
    if (interpreter->Invoke() != kTfLiteOk) {
        bsp_printf("[ML] Invoke failed\n\r");
        return ethernet_input(p, netif);
    }

    // 反量化输出
    float out_scale = model_output->params.scale;
    int   out_zp    = model_output->params.zero_point;
    int8_t raw      = model_output->data.int8[0];
    float score     = (raw - out_zp) * out_scale;

    bsp_printf("[ML] score=%.3f\r\n", score);

    // 简单阈值判断：score > 0.5 视为异常，丢包
    if (score > 0.5f) {
        bsp_printf("[ML-DROP] anomaly len=%lu proto=%u sport=%u dport=%u\r\n",
                   (unsigned long)p->tot_len, proto, sport, dport);
        pbuf_free(p);
        return ERR_OK;
    }

    // 否则放行
    return ethernet_input(p, netif);
}

/* ---------- LwIP + 网卡 初始化 ---------- */
void LwIP_Init(void)
{
    ip4_addr_t ipaddr, netmask, gw;
    IP4_ADDR(&ipaddr,   IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP4_ADDR(&netmask,  NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
    IP4_ADDR(&gw,       GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);

    lwip_init();
    netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL,
              ethernetif_init, sniff_input);
    netif_set_default(&gnetif);
    if (netif_is_link_up(&gnetif)) netif_set_up(&gnetif);
    else                           netif_set_down(&gnetif);

    // 同时启动 iperf 服务
    lwiperf_start_tcp_server(&ipaddr, 5001, NULL, NULL);
}

/* ---------- 中断 & Handler ---------- */
void trap_entry(void);
void userInterrupt(void);
void crash(void);

void interrupt_init(void)
{
    plic_set_threshold(BSP_PLIC, BSP_PLIC_CPU_0, 0);
    plic_set_priority( BSP_PLIC, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    plic_set_enable(   BSP_PLIC, BSP_PLIC_CPU_0, SYSTEM_PLIC_USER_INTERRUPT_A_INTERRUPT, 1);
    csr_write(mtvec,    (uint32_t)&trap_entry);
    csr_set(  mie,      MIE_MEIE);
    csr_write(mstatus,  MSTATUS_MPP | MSTATUS_MIE);
}

void trap(void)
{
    int32_t mc = csr_read(mcause);
    if (mc < 0 && (mc & 0xF) == CAUSE_MACHINE_EXTERNAL) userInterrupt();
    else                                                crash();
}

void userInterrupt(void)
{
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

void crash(void)
{
    bsp_printf("\r\n*** CRASH ***\r\n");
    while (1) { }
}

/* ---------- PHY & MAC ---------- */
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

    // PHY & MAC Reset
    MacRst(0,0);

    // 中断初始化
    interrupt_init();

    // DMA 优先级
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

    // TinyML Packet Filter 启动
    bsp_printf("TinyML Packet Filter Starting...\r\n");
    LwIP_Init();

    bsp_printf("iperf server Up\r\n");
    bsp_printf("IP: %d.%d.%d.%d   Netmask: %d.%d.%d.%d   GW: %d.%d.%d.%d   Speed: %d Mbps\r\n",
               IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3,
               NETMASK_ADDR0,NETMASK_ADDR1,NETMASK_ADDR2,NETMASK_ADDR3,
               GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3,
               link_speed);

    // 主循环
    extern int cur_des;  // 修改：cur_des 应为 int
    for (;;) {
        if (check_dma_status(cur_des)) {
            ethernetif_input(&gnetif);
        } else {
            int st = rtl8211_drv_rddata(26);
            if (!(st & 0x04) && bLink) {
                bLink = 0; bsp_printf("Disconnected\r\n");
            } else if ((st & 0x04) && !bLink) {
                speed = rtl8211_drv_linkup();
                clock_sel(speed);
                MacNormalInit(speed);
                bLink = 1; bsp_printf("Connected\r\n");
            }
            sys_check_timeouts();
        }
    }
}

/* =====================  end of main.c  ===================== */
