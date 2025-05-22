#ifndef EXTRACT_FEATURES_H
#define EXTRACT_FEATURES_H

#include <stdint.h>

/* 五欄位最小特徵向量 */
typedef struct {
    uint16_t eth_type;   /* 0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6… */
    uint8_t  ip_proto;   /* 6=TCP, 17=UDP, 1=ICMP…               */
    uint16_t src_port;   /* 0 當封包非 TCP/UDP                   */
    uint16_t dst_port;   /*                                   */
    uint16_t length;     /* 乙太封包總長度 (Byte)                */
} FeatureVec;

/* 解析封包 → 填入特徵向量；回傳 0 成功，<0 失敗 */
int extract_features(const uint8_t *pkt,
                     uint16_t      len,
                     FeatureVec   *fv);

#endif /* EXTRACT_FEATURES_H */
