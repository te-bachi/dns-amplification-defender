#include "log.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

bool log_enabled = true;

log_level_t LOG_CATEGORY_LEVEL[] = {
    [LOG_OBJECT]                = LOG_DEBUG,
    [LOG_DNS_DEFENDER]          = LOG_DEBUG,
    [LOG_SOCKET_BPF]            = LOG_DEBUG,
    [LOG_FIREWALL_PF]           = LOG_DEBUG,
    [LOG_HEADER_ETHERNET]       = LOG_DEBUG,
    [LOG_HEADER_IPV4]           = LOG_DEBUG,
    [LOG_HEADER_UDPV4]          = LOG_DEBUG,
    [LOG_HEADER_DNS]            = LOG_DEBUG
};

const char *LOG_CATEGORY_STRING[] = {
    [LOG_OBJECT]                = "[OBJECT           ]",
    [LOG_DNS_DEFENDER]          = "[DNS DEFENDER     ]",
    [LOG_SOCKET_BPF]            = "[SOCKET BPF       ]",
    [LOG_FIREWALL_PF]           = "[FIREWALL PF      ]",
    [LOG_HEADER_ETHERNET]       = "[HEADER ETHERNET  ]",
    [LOG_HEADER_IPV4]           = "[HEADER IPV4      ]",
    [LOG_HEADER_UDPV4]          = "[HEADER UDPV4     ]",
    [LOG_HEADER_DNS]            = "[HEADER DNS       ]"
};

const char *LOG_LEVEL_STRING[] = {
    [LOG_ERROR]                 = "[ERROR  ] ",
    [LOG_WARNING]               = "[WARN   ] ",
    [LOG_INFO]                  = "[INFO   ] ",
    [LOG_DEBUG]                 = "[DEBUG  ] ",
    [LOG_VERBOSE]               = "[VERBOSE] "
};

void
log_init(void)
{
    //
}

void 
log_enable(void)
{
    log_enabled = true;
}

void
log_disable(void)
{
    log_enabled = false;
}

/*** MESSAGES ****************************************************************/

/**
 * Print header information like time and category
 *
 * @param category      list of categories, see log.h
 * @param level         list of levels, see log.h
 */
void
log_print_header(log_category_t category, log_level_t level)
{
    time_t      now;
    struct tm   local;
    
    now = time(NULL);
    localtime_r(&now, &local);
    
    LOG_PRINTF(LOG_STREAM, "[%02" PRId8 ".%02" PRId8 ".%04" PRId8 " %02" PRId8 ":%02" PRId8 ":%02" PRId8 "]",
                           local.tm_mday, local.tm_mon, local.tm_year + 1900,
                           local.tm_hour, local.tm_min, local.tm_sec);

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

void
log_errno(int errnum)
{
    char error_str[STRERROR_R_BUFFER_MAX];
    
    if (!strerror_r(errnum, error_str, sizeof(error_str))) {
        LOG_PRINTF(LOG_STREAM, ": %s\n", error_str);
    } else {
        LOG_PRINTF(LOG_STREAM, ": <lookup error number failed>\n");
    }
}

