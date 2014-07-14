
#ifndef __PF_H__
#define __PF_H__

#include <netinet/in.h>

int  pf_add_ipv4_address(struct in_addr *addr);
int  pf_remove_ipv4_address(struct in_addr *addr);

#endif