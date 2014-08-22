
#include "dns_defender.h"
#include "log.h"
#include "log_network.h"
#include "bpf.h"
#include "pf.h"

#include "packet/packet.h"

#include <signal.h>
#include <errno.h>

typedef struct _dns_defender_t {
    bool                    running;
    int                     bpf;
    unsigned int            bpf_buf_len;
    netif_t                 netif;
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
    
    if (!netif_init(&dns_defender.netif, config->ifname)) {
        return false;
    }
    
    return true;
}

#define PACKET_SIZE  20

int
dns_defender_mainloop(void)
{
    packet_t       *packet[PACKET_SIZE];
    raw_packet_t    raw_packet;
    
    while (dns_defender.running) {
        if (bpf_read(dns_defender.bpf, &raw_packet, dns_defender.bpf_buf_len)) {
            LOG_RAW_PACKET(LOG_DNS_DEFENDER, LOG_INFO, &raw_packet, ("RX"));
            
            for (int i = 0; i < PACKET_SIZE; i++) {
                packet[i] = packet_decode(&dns_defender.netif, &raw_packet);
            }
            
            //log_packet(packet[0]);
            
            //for (int i = 0; i < 20; i++) {
                //log_packet(packet[i]);
            //}
            //log_ethernet_header(packet->ether);
            //log_ipv4_header(packet->ether->ipv4);
            //log_udpv4_header(packet->ether->ipv4->udpv4);
            //log_dns_header(packet->ether->ipv4->udpv4->dns);
            
            for (int i = 0; i < PACKET_SIZE; i++) {
                object_release(packet[i]);
            }
            dns_defender.running = false;
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
