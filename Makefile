
PROGRAMS                    = dnsdefend

CC                          = cc
GLOBAL_CFLAGS               = -O0 -pipe -Wall -ggdb -std=gnu99 -fms-extensions -Iinclude -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
GLOBAL_LDFLAGS              = 

### DNS-DEFEND ################################################################


dnsdefend_CFLAGS            = 
dnsdefend_LDFLAGS           = 
dnsdefend_SOURCE            = main.c \
                              object.c \
                              dns_defender.c \
                              bpf.c \
                              pf.c \
                              log.c \
                              log_network.c \
                              packet/net_address.c \
                              packet/network_interface.c \
                              packet/raw_packet.c \
                              packet/packet.c \
                              packet/header_storage.c \
                              packet/ethernet_header.c \
                              packet/ipv4_header.c \
                              packet/udpv4_header.c \
                              packet/dns_header.c

include Makefile.inc

