
#include "packet/packet.h"
#include "object.h"
#include "log.h"

static class_info_t class_info = {
    .size        = sizeof(packet_t),
    .destructor  = NULL,
    .mem_alloc   = malloc,
    .mem_free    = free
};

packet_t *
packet_new(void)
{
    packet_t *packet;
    
    if ((packet = object_new(&class_info)) == NULL) {
        return NULL;
    }
    
    return packet;
}

bool
packet_encode(packet_t *packet, raw_packet_t *raw_packet)
{
    raw_packet->len = ethernet_header_encode(packet->ether, raw_packet, 0);
    
    if (raw_packet->len == 0) {
        return false;
    }

    return true;
}

void
packet_decode(packet_t *packet, raw_packet_t *raw_packet)
{
    
    ethernet_header_decode(raw_packet, 0);
}

