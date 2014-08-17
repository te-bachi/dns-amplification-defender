
#include "packet/packet.h"
#include "object.h"
#include "log.h"

static void packet_destructor(void *ptr);

static class_info_t class_info = {
    .name       = "packet",
    .size       = sizeof(packet_t),
    .destructor = packet_destructor,
    .mem_alloc  = malloc,
    .mem_free   = free
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

static void
packet_destructor(void *ptr)
{
    packet_t *packet = (packet_t *) ptr;
    
    if (packet->head != NULL) {
        packet->head->klass->free(packet->head);
    }
}

bool
packet_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet)
{
    packet->tail = packet->head;
    raw_packet->len = ethernet_header_encode(netif, packet, raw_packet, 0);
    
    return (raw_packet->len == 0) ? false : true;
}

packet_t *
packet_decode(netif_t *netif, raw_packet_t *raw_packet)
{
    packet_t *packet = packet_new();
    packet->head = ethernet_header_decode(netif, packet, raw_packet, 0);
    
    return packet;
}

