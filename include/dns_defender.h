
#ifndef __DNS_DEFENDER_H__
#define __DNS_DEFENDER_H__

#include "config.h"

#include <stdint.h>
#include <stdbool.h>

bool            dns_defender_init(config_t *config);
int             dns_defender_mainloop(void);

#endif
