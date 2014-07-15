
#include "dns_defender.h"
#include "log.h"
#include "log_network.h"
#include "bpf.h"
#include "pf.h"

#include "packet/packet.h"

#include <signal.h>
#include <errno.h>

typedef struct _dns_defender_t {
    bool                running;
    int                 bpf;
    unsigned int        bpf_buf_len;
} dns_defender_t;

static dns_defender_t dns_defender;

static void dns_defender_int_signal(int signo);

bool
dns_defender_init(config_t *config)
{
    /* add signal handler */
    if (signal(SIGINT, dns_defender_int_signal) == SIG_ERR) {
        return false;
    }
    
    /* init log */
    log_init();
    
    /* open BPF device */
    dns_defender.bpf = bpf_open(config->ifname, config->timeout, &(dns_defender.bpf_buf_len));
    if (dns_defender.bpf == -1) {
        return false;
    }
    
    dns_defender.running = true;
    
    ipv4_address_t ipv4_address = { { .addr = { 192, 168, 0, 123 } } };
    
    pf_add_ipv4_address((struct in_addr *) &ipv4_address);
    //pf_remove_ipv4_address((struct in_addr *) &ipv4_address);
    
    return true;
}

/*
    raw_packet_t    raw_packet = {
        .len  = 70,
        .data = { 0x00, 0x15, 0x17, 0x0e, 0x61, 0xa2, 0x00, 0x03,
                  0x6c, 0xb3, 0x54, 0x1b, 0x08, 0x00, 0x45, 0x00,
                  0x00, 0x38, 0xfa, 0xd6, 0x00, 0x00, 0xf3, 0x11,
                  0x92, 0x32, 0xbc, 0x5f, 0x1d, 0xb1, 0xc3, 0x86,
                  0x9d, 0x14, 0xd5, 0x03, 0x00, 0x35, 0x00, 0x24,
                  0x00, 0x00, 0x46, 0x14, 0x01, 0x00, 0x00, 0x01,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                  0xff, 0x00, 0x01, 0x00, 0x00, 0x29, 0x23, 0x28,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };
    
    packet = packet_decode(&raw_packet);
    object_release(packet);
*/

int
dns_defender_mainloop(void)
{
    packet_t       *packet;
    raw_packet_t    raw_packet;
    
    while (dns_defender.running) {
        if (bpf_read(dns_defender.bpf, &raw_packet, dns_defender.bpf_buf_len)) {
            LOG_RAW_PACKET(LOG_DNS_DEFENDER, LOG_INFO, &raw_packet, ("RX"));
            packet = packet_decode(&raw_packet);
            log_ethernet_header(packet->ether);
            log_ipv4_header(packet->ether->ipv4);
            log_udpv4_header(packet->ether->ipv4->udpv4);
            log_dns_header(packet->ether->ipv4->udpv4->dns);
            object_release(packet);
        }
    }
    
    return 0;
}

static void
dns_defender_int_signal(int signo)
{
    LOG_PRINTLN(LOG_DNS_DEFENDER, LOG_INFO, ("\nCaught INT signal. Exit!"));
    dns_defender.running = false;
}
