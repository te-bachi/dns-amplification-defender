
#include "packet/packet.h"
#include "log.h"

#include <string.h>

packet_len_t
udpv4_header_encode(packet_t *packet, raw_packet_t *raw_packet, packet_offset_t udp_offset)
{
    udpv4_header_t *udpv4;
    packet_len_t    len;                        /* udp-header and payload length */
    uint16_t        ipv4_pseudo_size    = 0;
    packet_offset_t pseudo_offset       = 0;
    uint32_t        zero                = 0;
    
    /* decide */
    switch (udpv4->dest_port) {
        default:                                                                                                                return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    /* add udp-header to payload */
    len += UDPV4_HEADER_LEN;
    udpv4->len = len;
    
    uint16_to_uint8(&(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_SRC_PORT]),  &(udpv4->src_port));                                    /**< UDP Source Port */
    uint16_to_uint8(&(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_DEST_PORT]), &(udpv4->dest_port));                                   /**< UDP Destination port */
    uint16_to_uint8(&(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_LEN]),       &(udpv4->len));                                         /**< Packet Length (UDP Header + Payload) */
    
    /* reset checksum of raw packet */
    memcpy(&(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_CHECKSUM]), &(zero), sizeof(udpv4->checksum));
    
    /* calculate checksum over pseudo-ip-header, udp-header and payload */
    /* fill in pseudo-ip-header. the pseudo-ip-header will be overwritten by the real ip-header afterwards! */
    
    /* IPv4 pseudo-header */
    if (packet->ether->ipv4->version == IPV4_HEADER_VERSION) {
        pseudo_offset       = UDPV4_HEADER_PSEUDO_IPV4_SRC;
        ipv4_pseudo_size    = len;

        raw_packet->data[udp_offset - UDPV4_HEADER_PSEUDO_IPV4_PROTOCOL]                  = packet->ether->ipv4->protocol;                         /**< Protocol */
        uint16_to_uint8(&(raw_packet->data[udp_offset - UDPV4_HEADER_PSEUDO_IPV4_LEN]),   &(ipv4_pseudo_size));                               /**< UDP Length */
        memcpy(&(raw_packet->data[udp_offset - UDPV4_HEADER_PSEUDO_IPV4_SRC]),            &(packet->ether->ipv4->src),         IPV4_ADDRESS_LEN);  /**< Source IPv4 Address */
        memcpy(&(raw_packet->data[udp_offset - UDPV4_HEADER_PSEUDO_IPV4_DEST]),           &(packet->ether->ipv4->dest),        IPV4_ADDRESS_LEN);  /**< Destination IPv4 Address */
        memcpy(&(raw_packet->data[udp_offset - UDPV4_HEADER_PSEUDO_IPV4_ZERO]),           &(zero),                        1);                 /**< Zeros */
    } else {
        return 0;
    }
    
    /* check whether the UDP datagram length is an odd number */
    if (len % 2 == 1) {
        /* add a padding zero for checksum calculation and increase length by one */
        raw_packet->data[udp_offset + len] = 0;
        len += 1;
    }
    
    /* data = pseudo-ip-header + udp-header + payload
     *  len = pseudo-ip-header + udp-header + payload    */
    udpv4->checksum = raw_packet_calc_checksum((uint16_t *) &(raw_packet->data[udp_offset - pseudo_offset]), len + pseudo_offset);
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("encode UDP packet: checksum = 0x%04x, udp_offset = %u, pseudo_offset = %u, size = %u", ntohs(udpv4->checksum), udp_offset, pseudo_offset, len));
    
    /* set pseudo-ip-header to zero */
    memset(&(raw_packet->data[udp_offset - pseudo_offset]), 0, pseudo_offset);
    
    /* write checksum down to raw packet */
    uint16_to_uint8(&(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_CHECKSUM]),  &(udpv4->checksum));                                    /**< Checksum */
    
    return len;
}

/****************************************************************************
 * udpv4_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  udp_offset               offset from origin to udp packet
 ***************************************************************************/
void
udpv4_header_decode(packet_t *packet, raw_packet_t *raw_packet, packet_offset_t udp_offset)
{
    udpv4_header_t *udpv4;
    
    packet->type |= PACKET_TYPE_UDPV4;
    
    if (raw_packet->len < (udp_offset + UDPV4_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_ERROR, ("decode UDP packet: size too small (present=%u, required=%u)", raw_packet->len, (udp_offset + UDPV4_HEADER_LEN)));
        packet->type |= PACKET_TYPE_IGNORE;
        return;
    }
    
    /* pre-fetch */
    uint8_to_uint16(&(udpv4->dest_port), &(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_DEST_PORT]));
    
    /* decide */
    switch (udpv4->dest_port) {
        default:                    packet->type |= PACKET_TYPE_IGNORE;                                          return;
    }
    
    if (packet->type & PACKET_TYPE_IGNORE) {
        return;
    }
    
    /* fetch the rest */
    uint8_to_uint16(&(udpv4->src_port),  &(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_SRC_PORT]));
    uint8_to_uint16(&(udpv4->len),       &(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_LEN]));
    uint8_to_uint16(&(udpv4->checksum),  &(raw_packet->data[udp_offset + UDPV4_HEADER_OFFSET_CHECKSUM]));
    
    // TODO: Checksum (over pseudo-header, udp-header and payload) check
    
}

