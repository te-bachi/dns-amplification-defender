
#include "packet/ethernet_header.h"
#include "log.h"

#include <string.h>


static ethernet_header_t _ether;

ethernet_header_t *
ethernet_header_new(void)
{
    memset(&_ether, 0, sizeof(_ether));
    return &_ether;
}

void
ethernet_header_free(ethernet_header_t *ether)
{
    /* do nothing */
}

/****************************************************************************
 * ethernet_packet_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ethernet_header_encode(ethernet_header_t *ether, raw_packet_t *raw_packet, packet_offset_t ethernet_offset)
{
    uint16_t            ethertype;
    packet_len_t        ethernet_len;   /**< length of this packet */
    packet_len_t        len;            /**< length of the whole packet */
    
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
        case ETHERTYPE_IPV4:    len = ipv4_header_encode(ether->ipv4, raw_packet, ethernet_offset + ethernet_len);   break;
        default:                                                                                                return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    len += ethernet_len;

    memcpy(&(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_DEST]), ether->dest.addr, sizeof(ether->dest.addr));       /**< Destination MAC */
    memcpy(&(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_SRC]),  ether->src.addr,  sizeof(ether->src.addr));        /**< Source MAC */

    uint16_to_uint8(&(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_TYPE]), &(ether->type));                           /**< Ethernet Type / VLAN TPID */
        
    /* VLAN tag? */
    if (ether->type == ETHERTYPE_VLAN) {
        uint16_to_uint8(&(raw_packet->data[ethernet_offset + VLAN_HEADER_OFFSET_VLAN]), &(ether->vlan.tci));                       /**< VLAN Tag Control Information */
        uint16_to_uint8(&(raw_packet->data[ethernet_offset + VLAN_HEADER_OFFSET_TYPE]), &(ether->vlan.type));                      /**< Ethernet Type */
    }
    
    return len;
}

/****************************************************************************
 * ethernet_packet_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 ***************************************************************************/
ethernet_header_t *
ethernet_header_decode(raw_packet_t *raw_packet, packet_offset_t ethernet_offset)
{
    ethernet_header_t  *ether = ethernet_header_new();
    uint16_t            ethertype;
    packet_len_t        ethernet_len;   /**< length of this packet */
    
    //packet->type |= PACKET_TYPE_ETHERNET;
    
    if (raw_packet->len < (ethernet_offset + ETHERNET_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_ERROR, ("decode Ethernet packet: size too small (present=%u, required=%u)", raw_packet->len, ethernet_offset + ETHERNET_HEADER_LEN));
        //packet->type |= PACKET_TYPE_IGNORE;
        return NULL;
    }
    
    /* pre-fetch */
    uint8_to_uint16(&(ether->type), &(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_TYPE]));                           /**< Ethernet Type / VLAN TPID */
    
    /* VLAN tag? */
    if (ether->type == ETHERTYPE_VLAN) {
        
        uint8_to_uint16(&(ether->vlan.tci),  &(raw_packet->data[ethernet_offset + VLAN_HEADER_OFFSET_VLAN]));                      /**< VLAN Tag Control Information */
        uint8_to_uint16(&(ether->vlan.type), &(raw_packet->data[ethernet_offset + VLAN_HEADER_OFFSET_TYPE]));                      /**< Ethernet Type */

        LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_DEBUG, ("VLAN: tci=0x%04x vid=%u pcp=%u cfi=%u", ether->vlan.tci,
                                                                                              ether->vlan.vid,
                                                                                              ether->vlan.pcp,
                                                                                              ether->vlan.dei));

        ethertype           = ether->vlan.type;
        //packet->type       |= PACKET_TYPE_VLAN;
        ethernet_len        = VLAN_HEADER_LEN;

    } else {
        ethertype           = ether->type;
        ethernet_len        = ETHERNET_HEADER_LEN;
    }
    
    /* decide */
    switch(ethertype) {
        case ETHERTYPE_IPV4:    ether->ipv4 = ipv4_header_decode(raw_packet, ethernet_offset + ethernet_len);      break;
            
        default:                /* packet->type |= PACKET_TYPE_IGNORE;    */                  return NULL;
    }
    
    /*
    if (packet->type & PACKET_TYPE_IGNORE) {
        return NULL;
    }
    */
    
    /* fetch the rest */
    memcpy(ether->dest.addr,  &(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_DEST]), sizeof(ether->dest.addr));      /**< Destination MAC */
    memcpy(ether->src.addr,   &(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_SRC]),  sizeof(ether->src.addr));       /**< Source MAC */
    
    return ether;
}

