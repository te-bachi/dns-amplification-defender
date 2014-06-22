#include "log.h"

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>

bool log_enabled = false;

typedef struct log_date_t      log_date_t;
struct log_date_t {
    uint8_t     msec;
    uint8_t     sec;
    uint8_t     min;
    uint8_t     hour;
    uint8_t     day;
};

log_level_t LOG_CATEGORY_LEVEL[] = {
    [LOG_DNS_DEFENDER]             = LOG_ERROR,
    [LOG_SOCKET_BPF]               = LOG_ERROR,
    [LOG_FIREWALL_PF]              = LOG_ERROR,
    [LOG_HEADER_ETHERNET]          = LOG_ERROR,
    [LOG_HEADER_IPV4]              = LOG_ERROR,
    [LOG_HEADER_UDPV4]             = LOG_ERROR,
    [LOG_HEADER_DNS]               = LOG_ERROR
};

const char *LOG_CATEGORY_STRING[] = {
    [LOG_DNS_DEFENDER]             = "[DNS DEFENDER     ]",
    [LOG_SOCKET_BPF]               = "[SOCKET BPF       ]",
    [LOG_FIREWALL_PF]              = "[FIREWALL PF      ]",
    [LOG_HEADER_ETHERNET]          = "[HEADER ETHERNET  ]",
    [LOG_HEADER_IPV4]              = "[HEADER IPV4      ]",
    [LOG_HEADER_UDPV4]             = "[HEADER UDPV4     ]",
    [LOG_HEADER_DNS]               = "[HEADER DNS       ]"
};

const char *LOG_LEVEL_STRING[] = {
    [LOG_ERROR]                    = "[ERROR  ] ",
    [LOG_WARNING]                  = "[WARN   ] ",
    [LOG_INFO]                     = "[INFO   ] ",
    [LOG_DEBUG]                    = "[DEBUG  ] ",
    [LOG_VERBOSE]                  = "[VERBOSE] "
};

void
log_init()
{
    //
}

/*** MESSAGES ****************************************************************/

/**
 * Get time from the system-clock and calculate time information
 *
 * @param now           reference to a date structure
 */
static void log_date(log_date_t *now)
{
    /*
    now->day  = sys_sec   / (60 * 60 * 24);
    sys_sec  -= now->day  * (60 * 60 * 24);
    now->hour = sys_sec   / (60 * 60);
    sys_sec  -= now->hour * (60 * 60);
    now->min  = sys_sec   / (60);
    sys_sec  -= now->min  * (60);
    
    now->sec  = sys_sec;
    now->msec = sys_msec;
    */
}

/**
 * Print header information like time and category
 *
 * @param category      list of categories, see log.h
 * @param level         list of levels, see log.h
 */
void
log_print_header(log_category_t category, log_level_t level)
{
    
    log_date_t     now;

    log_date(&now);
    
    LOG_PRINTF(LOG_STREAM, "[%04" PRIu8 " %02" PRIu8 ":%02" PRIu8 ":%02" PRIu8 ".%03" PRIu8 "]", now.day, now.hour, now.min, now.sec, now.msec);

    LOG_HEADER_CATEGORY(category);
    LOG_HEADER_LEVEL(level);
}


void
log_print(const char *format, ...)
{   
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_println(const char *format, ...)
{
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_PRINTF(LOG_STREAM, "\n");
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_append(const char *format, ...)
{
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

void
log_appendln(const char *format, ...)
{
    va_list             args;
    
    va_start(args, format);
    LOG_VPRINTF(LOG_STREAM, format, args);
    LOG_PRINTF(LOG_STREAM, "\n");
    LOG_FLUSH(LOG_STREAM);
    va_end(args);
}

/*** TO STRING ***************************************************************/

