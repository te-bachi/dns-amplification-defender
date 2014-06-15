
#include "packet/ethernet_header.h"
#include "log.h"

#include <string.h>

/****************************************************************************
 * ethernet_packet_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ethernet_header_encode(packet_t *packet, raw_packet_t *raw_packet, packet_offset_t ethernet_offset)
{
    ethernet_header_t  *ether;
    uint16_t            ethertype;
    packet_len_t        ethernet_len;   /**< length of this packet */
    packet_len_t        len;            /**< length of the whole packet */
    
    /* set packet length (= part of offset to upper layer paket) */
    if (packet->type == ETHERTYPE_VLAN) {
        ethertype           = ether->vlan.type;
        ethernet_len        = VLAN_HEADER_LEN;
    } else {
        ethertype           = ether->type;
        ethernet_len        = ETHERNET_HEADER_LEN;
    }

    /* decide */
    switch(ethertype) {
        case ETHERTYPE_IPV4:    len = ipv4_header_encode(packet, raw_packet, ethernet_offset + ethernet_len);   break;
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
    if (packet->type == ETHERTYPE_VLAN) {
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
void
ethernet_header_decode(packet_t *packet, raw_packet_t *raw_packet, packet_offset_t ethernet_offset)
{
    ethernet_header_t  *ether;
    uint16_t            ethertype;
    packet_len_t        ethernet_len;   /**< length of this packet */
    
    packet->type |= PACKET_TYPE_ETHERNET;
    
    if (raw_packet->len < (ethernet_offset + ETHERNET_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_ERROR, ("decode Ethernet packet: size too small (present=%u, required=%u)", raw_packet->len, ethernet_offset + ETHERNET_HEADER_LEN));
        packet->type |= PACKET_TYPE_IGNORE;
        return;
    }
    
    /* pre-fetch */
    uint8_to_uint16(&(ether->type), &(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_TYPE]));                           /**< Ethernet Type / VLAN TPID */
    
    /* VLAN tag? */
    if (packet->type == ETHERTYPE_VLAN) {
        
        uint8_to_uint16(&(ether->vlan.tci),  &(raw_packet->data[ethernet_offset + VLAN_HEADER_OFFSET_VLAN]));                      /**< VLAN Tag Control Information */
        uint8_to_uint16(&(ether->vlan.type), &(raw_packet->data[ethernet_offset + VLAN_HEADER_OFFSET_TYPE]));                      /**< Ethernet Type */

        LOG_PRINTLN(LOG_HEADER_ETHERNET, LOG_DEBUG, ("VLAN: tci=0x%04x vid=%u pcp=%u cfi=%u", ether->vlan.tci, ether->vlan.vid, ether->vlan.pcp, ether->vlan.dei));

        ethertype           = ether->vlan.type;
        packet->type  |= PACKET_TYPE_VLAN;
        ethernet_len        = VLAN_HEADER_LEN;

    } else {
        ethertype           = ether->type;
        ethernet_len        = ETHERNET_HEADER_LEN;
    }
    
    /* decide */
    switch(ethertype) {
        case ETHERTYPE_IPV4:    ipv4_header_decode(packet, raw_packet, ethernet_offset + ethernet_len);      break;
            
        default:                packet->type |= PACKET_TYPE_IGNORE;                      return;
    }
    
    if (packet->type & PACKET_TYPE_IGNORE) {
        return;
    }
    
    /* fetch the rest */
    memcpy(ether->dest.addr,  &(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_DEST]), sizeof(ether->dest.addr));      /**< Destination MAC */
    memcpy(ether->src.addr,   &(raw_packet->data[ethernet_offset + ETHERNET_HEADER_OFFSET_SRC]),  sizeof(ether->src.addr));       /**< Source MAC */
}

