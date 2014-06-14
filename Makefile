
PROGRAMS                    = dns-defend

CC                          = gcc47
GLOBAL_CFLAGS               = -Wall -ggdb -Iinclude
GLOBAL_LDFLAGS              = 

### DNS-DEFEND ################################################################


dns-defend_CFLAGS           = 
dns-defend_LDFLAGS          = 
dns-defend_SOURCE           = main.c

include Makefile.inc

