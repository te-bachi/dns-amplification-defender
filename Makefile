
PROGRAMS                    = dns-defend

CC                          = gcc47
GLOBAL_CFLAGS               = -Wall -ggdb -std=gnu99 -fms-extensions -Iinclude
GLOBAL_LDFLAGS              = 

### DNS-DEFEND ################################################################


dns-defend_CFLAGS           = 
dns-defend_LDFLAGS          = 
dns-defend_SOURCE           = main.c \
                              dns-defend.c \
                              bpf.c \
                              pf.c \
                              packet/net_address.c \
                              packet/raw_packet.c \
                              packet/packet.c \
                              packet/ethernet_header.c \
                              packet/ipv4_header.c \
                              packet/udpv4_header.c \
                              packet/dns_header.c
                              

include Makefile.inc

