#include "lwip/init.h"
#include "lwip/netif.h"
#include "netif/ethernet.h"
#include "ethernetif.h"
#include "bsp.h"
#include "dmasg.h"
#include "mac.h"
#include "rtl8211fd_drv.h"
#include "uart.h"

/* ★ 新增 */
#include "extract_features.h"

/* 固定靜態 IP（同原範例，可照需求修改） */
#define IP_ADDR0 192
#define IP_ADDR1 168
#define IP_ADDR2 31
#define IP_ADDR3 55

static struct netif gnetif;
static uint32_t pkt_id = 0;

/* ======  DMA 描述子存取：依你 BSP 版本調整 ====== */
/* 回傳 0=無新封包，1=有；成功時填 buf/len 並釋放描述子 */
static int dma_get_packet(uint8_t **buf, uint16_t *len)
{
    if (!check_dma_status(cur_des))
        return 0;

    *buf = (uint8_t *)dma_get_buffer(cur_des);
    *len = dma_pkt_len(cur_des);
    dma_release_descriptor(cur_des);
    return 1;
}
/* ================================================= */

int main(void)
{
    /* ---- PHY & MAC 初始化 ---- */
    rtl8211_drv_init();
    int spd = rtl8211_drv_linkup();      /* 1G/100M/10M */
    clock_sel(spd);
    MacNormalInit(spd);

    /* ---- lwIP 基礎啟動（保留，之後可移除） ---- */
    ip4_addr_t ip, nm, gw;
    IP4_ADDR(&ip, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
    IP4_ADDR(&nm, 255,255,255,0);
    IP4_ADDR(&gw, IP_ADDR0, IP_ADDR1, IP_ADDR2, 1);
    lwip_init();
    netif_add(&gnetif, &ip, &nm, &gw, NULL,
              &ethernetif_init, &ethernet_input);
    netif_set_up(&gnetif);

    uart_printf("Feature-dumper ready …\r\n");

    /* ---- 主迴圈 ---- */
    for (;;)
    {
        uint8_t  *p;
        uint16_t  l;

        while (dma_get_packet(&p, &l))            /* 有新封包 */
        {
            FeatureVec fv;
            if (extract_features(p, l, &fv) == 0) /* 填特徵 */
            {
                uart_printf("Pkt%-6lu len=%4u eth=0x%04x "
                            "ip=%-2u sport=%-5u dport=%-5u\r\n",
                            pkt_id++, fv.length, fv.eth_type,
                            fv.ip_proto, fv.src_port, fv.dst_port);
            }
            ethernetif_input(&gnetif);            /* 丟給 lwIP */
        }

        sys_check_timeouts();                     /* lwIP 定時 */
    }
}
