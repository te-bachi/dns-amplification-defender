
#include "packet/packet.h"
#include "packet/port.h"
#include "log.h"

#include <string.h>

#define UDPV4_FAILURE_EXIT  udpv4_header_free((header_t *) udpv4); \
                            return NULL

static header_class_t       klass = {
    .type   = PACKET_TYPE_UDPV4,
    .size   = sizeof(udpv4_header_t),
    .free   = udpv4_header_free
};

static udpv4_header_t _udpv4;

udpv4_header_t *
udpv4_header_new(void)
{
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("UDPv4 header new"));
    
    memset(&_udpv4, 0, sizeof(udpv4_header_t));
    _udpv4.header.klass = &klass;
    return &_udpv4;
}

void
udpv4_header_free(header_t *header)
{
    if (header->next != NULL)   header->next->klass->free(header->next);
    
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("UDPv4 header free"));
}

packet_len_t
udpv4_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    ipv4_header_t  *ipv4;
    udpv4_header_t *udpv4;
    packet_len_t    len;                        /* udp-header and payload length */
    uint16_t        ipv4_pseudo_size    = 0;
    packet_offset_t pseudo_offset       = 0;
    uint32_t        zero                = 0;
    
    if (packet->tail->klass->type != PACKET_TYPE_IPV4 || packet->tail->next == NULL || packet->tail->next->klass->type != PACKET_TYPE_UDPV4) {
        return 0;
    }
    ipv4            = (ipv4_header_t *)  packet->tail;
    udpv4           = (udpv4_header_t *) packet->tail->next;
    packet->tail    = udpv4->header.next;
    
    /* decide */
    switch (udpv4->dest_port) {
        case PORT_DNS:      len = dns_header_encode(netif, packet, raw_packet, offset + UDPV4_HEADER_LEN);  break;
        default:                                                                                            return 0;
    }
    
    if (len == 0) {
        return 0;
    }
    
    /* add udp-header to payload */
    len += UDPV4_HEADER_LEN;
    udpv4->len = len;
    
    uint16_to_uint8(&(raw_packet->data[offset + UDPV4_HEADER_OFFSET_SRC_PORT]),  &(udpv4->src_port));                                    /**< UDP Source Port */
    uint16_to_uint8(&(raw_packet->data[offset + UDPV4_HEADER_OFFSET_DEST_PORT]), &(udpv4->dest_port));                                   /**< UDP Destination port */
    uint16_to_uint8(&(raw_packet->data[offset + UDPV4_HEADER_OFFSET_LEN]),       &(udpv4->len));                                         /**< Packet Length (UDP Header + Payload) */
    
    /* reset checksum of raw packet */
    memcpy(&(raw_packet->data[offset + UDPV4_HEADER_OFFSET_CHECKSUM]), &(zero), sizeof(udpv4->checksum));
    
    /* calculate checksum over pseudo-ip-header, udp-header and payload */
    /* fill in pseudo-ip-header. the pseudo-ip-header will be overwritten by the real ip-header afterwards! */
    
    /* IPv4 pseudo-header */
    if (ipv4->version == IPV4_HEADER_VERSION) {
        pseudo_offset       = UDPV4_HEADER_PSEUDO_IPV4_SRC;
        ipv4_pseudo_size    = len;
        
        raw_packet->data[offset - UDPV4_HEADER_PSEUDO_IPV4_PROTOCOL]                  = ipv4->protocol;                         /**< Protocol */
        uint16_to_uint8(&(raw_packet->data[offset - UDPV4_HEADER_PSEUDO_IPV4_LEN]),   &(ipv4_pseudo_size));                               /**< UDP Length */
        memcpy(&(raw_packet->data[offset - UDPV4_HEADER_PSEUDO_IPV4_SRC]),            &(ipv4->src),         IPV4_ADDRESS_LEN);  /**< Source IPv4 Address */
        memcpy(&(raw_packet->data[offset - UDPV4_HEADER_PSEUDO_IPV4_DEST]),           &(ipv4->dest),        IPV4_ADDRESS_LEN);  /**< Destination IPv4 Address */
        memcpy(&(raw_packet->data[offset - UDPV4_HEADER_PSEUDO_IPV4_ZERO]),           &(zero),                        1);                 /**< Zeros */
    } else {
        return 0;
    }
    
    /* check whether the UDP datagram length is an odd number */
    if (len % 2 == 1) {
        /* add a padding zero for checksum calculation and increase length by one */
        raw_packet->data[offset + len] = 0;
        len += 1;
    }
    
    /* data = pseudo-ip-header + udp-header + payload
     *  len = pseudo-ip-header + udp-header + payload    */
    udpv4->checksum = raw_packet_calc_checksum((uint16_t *) &(raw_packet->data[offset - pseudo_offset]), len + pseudo_offset);
    LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_DEBUG, ("encode UDP packet: checksum = 0x%04x, offset = %u, pseudo_offset = %u, size = %u", ntohs(udpv4->checksum), offset, pseudo_offset, len));
    
    /* set pseudo-ip-header to zero */
    memset(&(raw_packet->data[offset - pseudo_offset]), 0, pseudo_offset);
    
    /* write checksum down to raw packet */
    uint16_to_uint8(&(raw_packet->data[offset + UDPV4_HEADER_OFFSET_CHECKSUM]),  &(udpv4->checksum));                                    /**< Checksum */
    
    return len;
}

/****************************************************************************
 * udpv4_header_decode
 *
 * @param  this                     logical packet to be written
 * @param  raw_packet               raw packet to be read
 * @param  offset               offset from origin to udp packet
 ***************************************************************************/
header_t *
udpv4_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    udpv4_header_t *udpv4 = udpv4_header_new();
    
    if (raw_packet->len < (offset + UDPV4_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_UDPV4, LOG_ERROR, ("decode UDPv4 header: size too small (present=%u, required=%u)", raw_packet->len - offset, UDPV4_HEADER_LEN));
        UDPV4_FAILURE_EXIT;
    }
    
    /* fetch */
    uint8_to_uint16(&(udpv4->src_port),  &(raw_packet->data[offset + UDPV4_HEADER_OFFSET_SRC_PORT]));
    uint8_to_uint16(&(udpv4->dest_port), &(raw_packet->data[offset + UDPV4_HEADER_OFFSET_DEST_PORT]));
    uint8_to_uint16(&(udpv4->len),       &(raw_packet->data[offset + UDPV4_HEADER_OFFSET_LEN]));
    uint8_to_uint16(&(udpv4->checksum),  &(raw_packet->data[offset + UDPV4_HEADER_OFFSET_CHECKSUM]));
    
    /* decide */
    switch (udpv4->dest_port) {
        case PORT_DNS:      udpv4->header.next = dns_header_decode(netif, packet, raw_packet, offset + UDPV4_HEADER_LEN);       break;
        default:            UDPV4_FAILURE_EXIT;
    }
    
    if (udpv4->header.next == NULL) {
        UDPV4_FAILURE_EXIT;
    }
    
    // TODO: Checksum (over pseudo-header, udp-header and payload) check
    
    return (header_t *) udpv4;
}

