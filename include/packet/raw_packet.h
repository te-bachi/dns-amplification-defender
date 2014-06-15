#ifndef __RAW_PACKET_H__
#define __RAW_PACKET_H__

#include "object.h"
#include "net_address.h"

typedef struct _raw_packet_t {
    object_t            obj;
    uint16_t            len;
    union {
        uint8_t         data[ETH_MAX_FRAME_SIZE];
        uint32_t        data32[ETH_MAX_FRAME_SIZE / 4];
    };
} raw_packet_t;

raw_packet_t *raw_packet_new(void);
bool          raw_packet_init(raw_packet_t *raw_packet);
uint16_t      raw_packet_calc_checksum(uint16_t *buffer, uint16_t len);

#endif
