#ifndef __PACKET_FACTORY_H__
#define __PACKET_FACTORY_H__

#include "packet/packet.h"

typedef struct _packet_storage_t packet_storage_t;

struct _packet_storage_t {
    header_class_t     *klass;
    header_t           *assigned;
    uint32_t            assigned_size;
    header_t           *available;
    uint32_t            available_size;
    packet_storage_t   *next;
};

header_t   *packet_storage_assign(packet_storage_t *storage);
void        packet_storage_return(packet_storage_t *storage, header_t *header);

#endif

