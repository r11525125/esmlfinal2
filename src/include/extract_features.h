#ifndef EXTRACT_FEATURES_H
#define EXTRACT_FEATURES_H
#include <stdint.h>

typedef struct {
    uint16_t eth_type;
    uint8_t  ip_proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
} FeatureVec;

int extract_features(const uint8_t *pkt, uint16_t len, FeatureVec *fv);
#endif
