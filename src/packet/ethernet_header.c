
#include "packet/ethernet_header.h"
#include "packet/header_storage.h"
#include "log.h"

#include <string.h>
#include <inttypes.h>

#define ETHERNET_STORAGE_INIT_SIZE      2
#define ETHERNET_FAILURE_EXIT           ethernet_header_free((header_t *) ether); \
                                        return NULL

static ethernet_header_t        ether[ETHERNET_STORAGE_INIT_SIZE];
static uint32_t                 idx[ETHERNET_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = PACKET_TYPE_ETHERNET,
    .size               = sizeof(ethernet_header_t),
    .free               = ethernet_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) ether,
    .allocator_size     = ETHERNET_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = ETHERNET_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .start              = &entry
};

ethernet_header_t *
ethernet_header_new(void)
{
    ethernet_header_t *header = (ethernet_header_t *) header_storage_new(&storage);
    
    LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_DEBUG, ("Ethernet header new %016" PRIxPTR, (unsigned long) header));
    
    return header;
}

void
ethernet_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);
    
    LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_DEBUG, ("Ethernet header free %016" PRIxPTR, (unsigned long) header));
    
    header_storage_free(header);
}

/****************************************************************************
 * ethernet_packet_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ethernet_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ethernet_header_t  *ether;
    uint16_t            ethertype;
    packet_len_t        ethernet_len;   /**< length of this header */
    packet_len_t        len;            /**< length of the whole packet */
    
    if (packet->tail->klass->type != PACKET_TYPE_ETHERNET) {
        return 0;
    }
    ether           = (ethernet_header_t *) packet->tail;
    packet->tail    = ether->header.next;
    
    /* set packet length (= part of offset to upper layer paket) */
    if (ether->type == ETHERTYPE_VLAN) {
        ethertype           = ether->vlan.type;
        ethernet_len        = VLAN_HEADER_LEN;
    } else {
        ethertype           = ether->type;
        ethernet_len        = ETHERNET_HEADER_LEN;
    }
    
    /* decide */
    switch(ethertype) {
        case ETHERTYPE_IPV4:    len = ipv4_header_encode(netif, packet, raw_packet, offset + ethernet_len);         break;
        default:                                                                                                    return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    len += ethernet_len;
    
    memcpy(&(raw_packet->data[offset + ETHERNET_HEADER_OFFSET_DEST]), ether->dest.addr, sizeof(ether->dest.addr));       /**< Destination MAC */
    memcpy(&(raw_packet->data[offset + ETHERNET_HEADER_OFFSET_SRC]),  ether->src.addr,  sizeof(ether->src.addr));        /**< Source MAC */
    
    uint16_to_uint8(&(raw_packet->data[offset + ETHERNET_HEADER_OFFSET_TYPE]), &(ether->type));                           /**< Ethernet Type / VLAN TPID */
    
    /* VLAN tag? */
    if (ether->type == ETHERTYPE_VLAN) {
        uint16_to_uint8(&(raw_packet->data[offset + VLAN_HEADER_OFFSET_VLAN]), &(ether->vlan.tci));                       /**< VLAN Tag Control Information */
        uint16_to_uint8(&(raw_packet->data[offset + VLAN_HEADER_OFFSET_TYPE]), &(ether->vlan.type));                      /**< Ethernet Type */
    }
    
    return len;
}

/****************************************************************************
 * ethernet_packet_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 ***************************************************************************/
header_t *
ethernet_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ethernet_header_t  *ether = ethernet_header_new();
    uint16_t            ethertype;
    packet_len_t        ethernet_len;   /**< length of this packet */
    
    if (raw_packet->len < (offset + ETHERNET_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_ERROR, ("decode Ethernet header: size too small (present=%u, required=%u)", raw_packet->len - offset, ETHERNET_HEADER_LEN));
        ETHERNET_FAILURE_EXIT;
    }
    
    /* fetch */
    memcpy(ether->dest.addr,  &(raw_packet->data[offset + ETHERNET_HEADER_OFFSET_DEST]), sizeof(ether->dest.addr));     /**< Destination MAC */
    memcpy(ether->src.addr,   &(raw_packet->data[offset + ETHERNET_HEADER_OFFSET_SRC]),  sizeof(ether->src.addr));      /**< Source MAC */
    uint8_to_uint16(&(ether->type), &(raw_packet->data[offset + ETHERNET_HEADER_OFFSET_TYPE]));                         /**< Ethernet Type / VLAN TPID */
    
    LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_INFO, ("ethertype=0x%04x", ether->type));
    
    /* VLAN tag? */
    if (ether->type == ETHERTYPE_VLAN) {
        
        uint8_to_uint16(&(ether->vlan.tci),  &(raw_packet->data[offset + VLAN_HEADER_OFFSET_VLAN]));                    /**< VLAN Tag Control Information */
        uint8_to_uint16(&(ether->vlan.type), &(raw_packet->data[offset + VLAN_HEADER_OFFSET_TYPE]));                    /**< Ethernet Type */
        
        LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_DEBUG, ("VLAN: tci=0x%04x vid=%u pcp=%u cfi=%u", ether->vlan.tci,
                                                                                              ether->vlan.vid,
                                                                                              ether->vlan.pcp,
                                                                                              ether->vlan.dei));
        
        ethertype           = ether->vlan.type;
        ethernet_len        = VLAN_HEADER_LEN;
        
    } else {
        ethertype           = ether->type;
        ethernet_len        = ETHERNET_HEADER_LEN;
    }
    
    /* decide */
    switch(ethertype) {
        case ETHERTYPE_IPV4:    ether->header.next = ipv4_header_decode(netif, packet, raw_packet, offset + ethernet_len);  break;
        default:                                                                                                    ETHERNET_FAILURE_EXIT;
    }
    
    if (ether->header.next == NULL) {
        ETHERNET_FAILURE_EXIT;
    }
    
    return (header_t *) ether;
}

