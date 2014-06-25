#include "packet/packet.h"
#include "log.h"

#include <string.h>

const static uint16_t CHECKSUM_ZERO = 0x0000;

static ipv4_header_t ipv4_header;

ipv4_header_t *
ipv4_header_new(void)
{
    memset(&ipv4_header, 0, sizeof(ipv4_header_t));
    return &ipv4_header;
}
void
ipv4_header_free(ipv4_header_t *ipv4_header)
{
    /* do nothing */
}

/****************************************************************************
 * ip_packet_encode
 *
 * @param  this                     logical packet to be read
 * @param  raw_packet               raw packet to be written
 * @param  ipv4_offset                offset from origin to ip packet
 * @return                          number of bytes written to raw packet
 ***************************************************************************/
packet_len_t
ipv4_header_encode(packet_t *packet, raw_packet_t *raw_packet, packet_offset_t ipv4_offset)
{
    ipv4_header_t  *ipv4 = packet->ether->ipv4;
    packet_len_t    len;
    
    /* IPv4 */
    if (ipv4->version != IPV4_HEADER_VERSION) {
        return 0;
    }
    
    /* decide */
    switch (ipv4->protocol) {
        case IPV4_PROTOCOL_UDP:     len = udpv4_header_encode(packet, raw_packet, ipv4_offset + IPV4_HEADER_LEN);   break;
        default:                                                                                                            return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    len += IPV4_HEADER_LEN;
    
    /* calculate length */
    ipv4->len = len;

    raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_VERSION]      = ipv4->ver_ihl;                                              /**< IP version */
    raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_TOS]        = ipv4->tos;                                             /**< TOS (Type of Service) */
    raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_TTL]        = ipv4->ttl;                                             /**< TTL (Time to Live) */
    raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_PROTOCOL]   = ipv4->protocol;                                        /**< IPv4 protocol */
    uint16_to_uint8(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_LEN]),        &(ipv4->len));                       /**< Total Length */
    uint16_to_uint8(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_ID]),         &(ipv4->id));                        /**< Identification */
    uint16_to_uint8(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_FLAGS]),      &(ipv4->flags_offset));              /**< Flags + Fragment Offset */
    memcpy(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_SRC]),         &(ipv4->src.addr),  sizeof(ipv4_address_t)); /**< Source Address */
    memcpy(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_DEST]),        &(ipv4->dest.addr), sizeof(ipv4_address_t)); /**< Destination Address */
    
    /* reset checksum (set to zero) */
    memcpy(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_CHECKSUM]),    &CHECKSUM_ZERO,            sizeof(uint16_t));       /**< Header Checksum to Zero */

    /* calculate checksum over ip-header */
    ipv4->checksum = raw_packet_calc_checksum((uint16_t *) &(raw_packet->data[ipv4_offset]), IPV4_HEADER_LEN);
    uint16_to_uint8(&(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_CHECKSUM]),   &(ipv4->checksum));                  /**< Header Checksum */
    
    return len;
}

/****************************************************************************
 * ip_packet_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  ipv4_offset                offset from origin to ip packet
 ***************************************************************************/
void
ipv4_header_decode(packet_t *packet, raw_packet_t *raw_packet, packet_offset_t ipv4_offset)
{
    ipv4_header_t  *ipv4 = ipv4_header_new();
    
    /* add IPv4 address */
    packet->ether->ipv4 = ipv4;
    
    /* pre-pre-fetch */
    ipv4->ver_ihl             = raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_VERSION];                                 /**< IP version */
    
    if (ipv4->version == IPV4_HEADER_VERSION) {
        
        packet->type |= PACKET_TYPE_IPV4;
        
        if (raw_packet->len < (ipv4_offset + IPV4_HEADER_LEN)) {
            LOG_PRINTLN(LOG_HEADER_IPV4, LOG_ERROR, ("decode IPv4 packet: size too small (present=%u, required=%u)", raw_packet->len, (ipv4_offset + IPV4_HEADER_LEN)));
            packet->type |= PACKET_TYPE_IGNORE;
            return;
        }
        
        /* pre-fetch */
        ipv4->protocol   = raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_PROTOCOL];                                     /**< IPv4 protocol */

        /* decide */
        switch (ipv4->protocol) {
            case IPV4_PROTOCOL_UDP:     udpv4_header_decode(packet, raw_packet, ipv4_offset + IPV4_HEADER_LEN);   break;
            default:                    packet->type |= PACKET_TYPE_IGNORE;                                          return;
        }
        
        if (packet->type & PACKET_TYPE_IGNORE) {
            return;
        }
        
        /* fetch the rest */
        ipv4->tos        = raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_TOS];                                          /**< TOS (Type of Service) */
        ipv4->ttl        = raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_TTL];                                          /**< TTL (Time to Live) */
        uint8_to_uint16(&(ipv4->len),            &(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_LEN]));                /**< Total Length */
        uint8_to_uint16(&(ipv4->id),             &(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_ID]));                 /**< Identification */
        uint8_to_uint16(&(ipv4->flags_offset),   &(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_FLAGS]));              /**< Flags + Fragment Offset */
        uint8_to_uint16(&(ipv4->checksum),       &(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_CHECKSUM]));           /**< Header Checksum */
        memcpy(&(ipv4->src.addr),  &(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_SRC]),  IPV4_ADDRESS_LEN);           /**< Source Address */
        memcpy(&(ipv4->dest.addr), &(raw_packet->data[ipv4_offset + IPV4_HEADER_OFFSET_DEST]), IPV4_ADDRESS_LEN);           /**< Destination Address */
        
        // TODO: Checksum (over ip-header) check
        
    } else {
        LOG_PRINTLN(LOG_HEADER_IPV4, LOG_ERROR, ("no IPv4 header ?! raw=%u version=%u", ipv4->ver_ihl, ipv4->version));
        packet->type |= PACKET_TYPE_IGNORE;
    }
}

