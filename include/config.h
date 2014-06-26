
#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct _config_t {
    char           *ifname;
    unsigned int    timeout;
    
} config_t;

#endif

