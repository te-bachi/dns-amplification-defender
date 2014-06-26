
#ifndef __LOG_H__
#define __LOG_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/*** DEFINES ****************************************************************/

#define LOG_STREAM                      stderr
#define LOG_PRINTF                      fprintf
#define LOG_VPRINTF                     vfprintf
#define LOG_FLUSH                       fflush

#define STRERROR_R_BUFFER_MAX           64

/*** MACROS *****************************************************************/

#define LOG_FUNCTION(with_header, function, category, level, msg) \
    do { \
        if (log_enabled && level <= LOG_CATEGORY_LEVEL[category]) { \
            if (with_header) { \
                log_print_header(category, level); \
            } \
            function msg; \
        } \
    } while(0)

/*
#define LOG_CHAR_STREAM(category, level, stream, len, msg) \
    do { \
        if (log_enabled && level <= LOG_CATEGORY_LEVEL[category]) { \
            log_print_header(category, level); \
            log_print msg; \
            log_char_stream(stream, len); \
        } \
    } while(0)
*/

#define LOG_ERRNO(category, level, errnum, msg) \
    do { \
        if (log_enabled && level <= LOG_CATEGORY_LEVEL[category]) { \
            log_print_header(category, level); \
            log_print msg; \
            log_errno(errnum); \
        } \
    } while(0)

#define LOG_ENABLE(category, level)             (log_enabled && level <= LOG_CATEGORY_LEVEL[category])

#define LOG_HEADER_CATEGORY(category)           LOG_PRINTF(LOG_STREAM, "%s", LOG_CATEGORY_STRING[category]);
#define LOG_HEADER_LEVEL(level)                 LOG_PRINTF(LOG_STREAM, "%s", LOG_LEVEL_STRING[level]);

#define LOG_PRINT(category, level, msg)         LOG_FUNCTION(true,  log_print,         category, level, msg)
#define LOG_PRINTLN(category, level, msg)       LOG_FUNCTION(true,  log_println,       category, level, msg)
#define LOG_APPEND(category, level, msg)        LOG_FUNCTION(false, log_append,        category, level, msg)
#define LOG_APPENDLN(category, level, msg)      LOG_FUNCTION(false, log_appendln,      category, level, msg)

/*** DECLARATION ************************************************************/

typedef enum {
    LOG_OBJECT,
    LOG_DNS_DEFENDER,
    LOG_SOCKET_BPF,
    LOG_FIREWALL_PF,
    LOG_HEADER_ETHERNET,
    LOG_HEADER_IPV4,
    LOG_HEADER_UDPV4,
    LOG_HEADER_DNS,
} log_category_t;

typedef enum {
    LOG_ERROR          = 0,
    LOG_WARNING        = 1,
    LOG_INFO           = 2,
    LOG_DEBUG          = 3,
    LOG_VERBOSE        = 4
} log_level_t;

/*** DEFINITION *************************************************************/

extern log_level_t      LOG_CATEGORY_LEVEL[];
extern const char      *LOG_CATEGORY_STRING[];
extern const char      *LOG_LEVEL_STRING[];
extern bool             log_enabled;                /**< don't use it directly! use functions */

void log_init();

static inline void log_enable()  { log_enabled = true;  }
static inline void log_disable() { log_enabled = false; }

void        log_print_header           (log_category_t category, log_level_t level);
void        log_print                  (const char *format, ...)                __attribute__ ((format (printf, 1, 2)));
void        log_println                (const char *format, ...)                __attribute__ ((format (printf, 1, 2)));
void        log_errno                  (int errnum);
void        log_append                 (const char *format, ...)                __attribute__ ((format (printf, 1, 2)));
void        log_appendln               (const char *format, ...)                __attribute__ ((format (printf, 1, 2)));
/* void        log_char_stream            (const char *stream, const uint32_t len); */

#endif

