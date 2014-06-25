
#include "packet/packet.h"
#include "packet/port.h"
#include "log.h"

#include <string.h>

#define UDPV4_FAILURE_EXIT  udpv4_header_free(udpv4); \
                            return NULL
                            
static udpv4_header_t udpv4_header;

udpv4_header_t *
udpv4_header_new(void)
{
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("UDPv4 header new"));
    
    memset(&udpv4_header, 0, sizeof(udpv4_header_t));
    return &udpv4_header;
}

void
udpv4_header_free(udpv4_header_t *udpv4)
{
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("UDPv4 header free"));
    
    if (udpv4->dns != NULL)     dns_header_free(udpv4->dns);
}

packet_len_t
udpv4_header_encode(ipv4_header_t *ipv4, raw_packet_t *raw_packet, packet_offset_t udpv4_offset)
{
    udpv4_header_t *udpv4 = ipv4->udpv4;
    packet_len_t    len;                        /* udp-header and payload length */
    uint16_t        ipv4_pseudo_size    = 0;
    packet_offset_t pseudo_offset       = 0;
    uint32_t        zero                = 0;
    
    /* decide */
    switch (udpv4->dest_port) {
        case PORT_DNS:      len = dns_header_encode(udpv4->dns, raw_packet, udpv4_offset + UDPV4_HEADER_LEN);   break;
        default:                                                                                            return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    /* add udp-header to payload */
    len += UDPV4_HEADER_LEN;
    udpv4->len = len;
    
    uint16_to_uint8(&(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_SRC_PORT]),  &(udpv4->src_port));                                    /**< UDP Source Port */
    uint16_to_uint8(&(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_DEST_PORT]), &(udpv4->dest_port));                                   /**< UDP Destination port */
    uint16_to_uint8(&(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_LEN]),       &(udpv4->len));                                         /**< Packet Length (UDP Header + Payload) */
    
    /* reset checksum of raw packet */
    memcpy(&(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_CHECKSUM]), &(zero), sizeof(udpv4->checksum));
    
    /* calculate checksum over pseudo-ip-header, udp-header and payload */
    /* fill in pseudo-ip-header. the pseudo-ip-header will be overwritten by the real ip-header afterwards! */
    
    /* IPv4 pseudo-header */
    if (ipv4->version == IPV4_HEADER_VERSION) {
        pseudo_offset       = UDPV4_HEADER_PSEUDO_IPV4_SRC;
        ipv4_pseudo_size    = len;
        
        raw_packet->data[udpv4_offset - UDPV4_HEADER_PSEUDO_IPV4_PROTOCOL]                  = ipv4->protocol;                         /**< Protocol */
        uint16_to_uint8(&(raw_packet->data[udpv4_offset - UDPV4_HEADER_PSEUDO_IPV4_LEN]),   &(ipv4_pseudo_size));                               /**< UDP Length */
        memcpy(&(raw_packet->data[udpv4_offset - UDPV4_HEADER_PSEUDO_IPV4_SRC]),            &(ipv4->src),         IPV4_ADDRESS_LEN);  /**< Source IPv4 Address */
        memcpy(&(raw_packet->data[udpv4_offset - UDPV4_HEADER_PSEUDO_IPV4_DEST]),           &(ipv4->dest),        IPV4_ADDRESS_LEN);  /**< Destination IPv4 Address */
        memcpy(&(raw_packet->data[udpv4_offset - UDPV4_HEADER_PSEUDO_IPV4_ZERO]),           &(zero),                        1);                 /**< Zeros */
    } else {
        return 0;
    }
    
    /* check whether the UDP datagram length is an odd number */
    if (len % 2 == 1) {
        /* add a padding zero for checksum calculation and increase length by one */
        raw_packet->data[udpv4_offset + len] = 0;
        len += 1;
    }
    
    /* data = pseudo-ip-header + udp-header + payload
     *  len = pseudo-ip-header + udp-header + payload    */
    udpv4->checksum = raw_packet_calc_checksum((uint16_t *) &(raw_packet->data[udpv4_offset - pseudo_offset]), len + pseudo_offset);
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("encode UDP packet: checksum = 0x%04x, udpv4_offset = %u, pseudo_offset = %u, size = %u", ntohs(udpv4->checksum), udpv4_offset, pseudo_offset, len));
    
    /* set pseudo-ip-header to zero */
    memset(&(raw_packet->data[udpv4_offset - pseudo_offset]), 0, pseudo_offset);
    
    /* write checksum down to raw packet */
    uint16_to_uint8(&(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_CHECKSUM]),  &(udpv4->checksum));                                    /**< Checksum */
    
    return len;
}

/****************************************************************************
 * udpv4_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  udpv4_offset               offset from origin to udp packet
 ***************************************************************************/
udpv4_header_t *
udpv4_header_decode(raw_packet_t *raw_packet, packet_offset_t udpv4_offset)
{
    udpv4_header_t *udpv4 = udpv4_header_new();
    
    if (raw_packet->len < (udpv4_offset + UDPV4_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_ERROR, ("decode UDP packet: size too small (present=%u, required=%u)", raw_packet->len, (udpv4_offset + UDPV4_HEADER_LEN)));
        UDPV4_FAILURE_EXIT;
    }
    
    /* pre-fetch */
    uint8_to_uint16(&(udpv4->dest_port), &(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_DEST_PORT]));
    
    /* decide */
    switch (udpv4->dest_port) {
        case PORT_DNS:      udpv4->dns = dns_header_decode(raw_packet, udpv4_offset + UDPV4_HEADER_LEN);    break;
        default:                                                                                            UDPV4_FAILURE_EXIT;
    }
    
    if (udpv4->dns == NULL) {
        UDPV4_FAILURE_EXIT;
    }
    
    /* fetch the rest */
    uint8_to_uint16(&(udpv4->src_port),  &(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_SRC_PORT]));
    uint8_to_uint16(&(udpv4->len),       &(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_LEN]));
    uint8_to_uint16(&(udpv4->checksum),  &(raw_packet->data[udpv4_offset + UDPV4_HEADER_OFFSET_CHECKSUM]));
    
    // TODO: Checksum (over pseudo-header, udp-header and payload) check
    
    return udpv4;
}

