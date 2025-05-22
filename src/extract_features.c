#include "extract_features.h"

/* big-endian 16-bit 讀取輔助 */
static inline uint16_t be16(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint16_t)b[0] << 8) | b[1];
}

int extract_features(const uint8_t *pkt,
                     uint16_t      len,
                     FeatureVec   *fv)
{
    if (len < 14) return -1;             /* Ethernet header 不完整 */

    fv->eth_type = be16(pkt + 12);
    fv->length   = len;

    /* 只處理 IPv4 封包，其餘協定直接回傳 */
    if (fv->eth_type != 0x0800 || len < 34) {
        fv->ip_proto = 0;
        fv->src_port = fv->dst_port = 0;
        return 0;
    }

    /* ---------- IPv4 ---------- */
    uint8_t ihl = (pkt[14] & 0x0F) * 4;  /* Header 長度 (byte) */
    fv->ip_proto = pkt[23];              /* Protocol 欄位 */

    /* 只解析 TCP/UDP 端口，其餘設 0 */
    if ((fv->ip_proto == 6 || fv->ip_proto == 17) &&
        len >= 14 + ihl + 4)
    {
        const uint8_t *l4 = pkt + 14 + ihl;
        fv->src_port = be16(l4);
        fv->dst_port = be16(l4 + 2);
    } else {
        fv->src_port = fv->dst_port = 0;
    }
    return 0;
}
