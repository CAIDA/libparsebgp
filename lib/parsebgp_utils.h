#ifndef __PARSEBGP_UTILS_H
#define __PARSEBGP_UTILS_H

#include "parsebgp_error.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// for inet_ntop:
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/** Internal to the STR macro */
#define XSTR(a) #a

/** Stringify a macro value */
#define STR(a) XSTR(a)

/* ntholl and htonll macros from
   http://www.codeproject.com/KB/cpp/endianness.aspx */
/** Byte-swap a 64-bit integer */
#ifndef ntohll
#define ntohll(x)                                                              \
  (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) |                         \
   (uint32_t)ntohl(((int)(x >> 32))))
#endif

/** Byte-swap a 64-bit integer */
#ifndef htonll
#define htonll(x) ntohll(x)
#endif

/** Convenience macro to deserialize a simple variable from a byte array.
 *
 * @param buf           pointer to the buffer (will be updated)
 * @param len           total length of the buffer
 * @param read          the number of bytes already read from the buffer
 *                      (will be updated)
 * @param to            the variable to deserialize
 */
#define PARSEBGP_DESERIALIZE_VAL(buf, len, read, to)                           \
  do {                                                                         \
    if (((len) - (read)) < sizeof(to)) {                                       \
      return PARSEBGP_PARTIAL_MSG;                                             \
    }                                                                          \
    memcpy(&(to), (buf), sizeof(to));                                          \
    read += sizeof(to);                                                        \
    buf += sizeof(to);                                                         \
  } while (0)

/** Convenience macro to either abort parsing or skip an unimplemented feature
    depending on run-time configuration */
#define PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain, msg_fmt, ...)  \
  do {                                                                         \
    if ((opts)->ignore_not_implemented) {                                      \
      nread += (remain);                                                       \
      buf += (remain);                                                         \
      fprintf(stderr, "WARN: NOT_IMPLEMENTED: " msg_fmt " (%s:%d)\n",          \
              __VA_ARGS__, __FILE__, __LINE__);                                \
    } else {                                                                   \
      fprintf(stderr, "ERROR: NOT_IMPLEMENTED: " msg_fmt " (%s:%d)\n",         \
              __VA_ARGS__, __FILE__, __LINE__);                                \
      return PARSEBGP_NOT_IMPLEMENTED;                                         \
    }                                                                          \
  } while (0)

#define PARSEBGP_DUMP_STRUCT_HDR(struct_name, depth)                           \
  do {                                                                         \
    int i;                                                                     \
    for (i = 0; i < depth; i++) {                                              \
      if (i == depth - 1) {                                                    \
        printf(" ");                                                           \
      } else {                                                                 \
        printf("  ");                                                          \
      }                                                                        \
    }                                                                          \
    printf(">> " STR(struct_name) " (%ld bytes):\n", sizeof(struct_name));     \
  } while (0)

#define PARSEBGP_DUMP_INFO(depth, ...)                                         \
  do {                                                                         \
    int i;                                                                     \
    printf(" ");                                                               \
    for (i = 0; i < depth; i++) {                                              \
      printf("  ");                                                            \
    }                                                                          \
    printf(__VA_ARGS__);                                                       \
  } while (0)

#define PARSEBGP_DUMP_INT(depth, name, val)                                    \
  PARSEBGP_DUMP_INFO(depth, name ": %*d\n", 20 - (int)strlen(name ": "),       \
                     (int)val);

#define PARSEBGP_DUMP_IP(depth, name, afi, ipaddr)                             \
  do {                                                                         \
    int mapping[] = {-1, AF_INET, AF_INET6};                                   \
    char ip_buf[INET6_ADDRSTRLEN];                                             \
    inet_ntop(mapping[afi], ipaddr, ip_buf, INET6_ADDRSTRLEN);                 \
    PARSEBGP_DUMP_INFO(depth, name ": %*s\n", 20 - (int)strlen(name ": "),     \
                       ip_buf);                                                \
  } while (0)

#define PARSEBGP_DUMP_PFX(depth, name, afi, ipaddr, len)                       \
  do {                                                                         \
    int mapping[] = {-1, AF_INET, AF_INET6};                                   \
    char ip_buf[INET6_ADDRSTRLEN];                                             \
    inet_ntop(mapping[afi], ipaddr, ip_buf, INET6_ADDRSTRLEN);                 \
    PARSEBGP_DUMP_INFO(depth, name ": %*s/%d\n", 20 - (int)strlen(name ": "),  \
                       ip_buf, len);                                           \
  } while (0)

#define PARSEBGP_DUMP_DATA(depth, name, data, len)                             \
  do {                                                                         \
    int _byte;                                                                 \
    PARSEBGP_DUMP_INFO(depth, name ": ");                                      \
    if ((len) == 0) {                                                          \
      printf("NONE\n");                                                        \
    } else {                                                                   \
      for (_byte = 0; _byte < len; _byte++) {                                  \
        if (_byte != 0) {                                                      \
          printf(" ");                                                         \
        }                                                                      \
        printf("%02X", data[_byte]);                                           \
      }                                                                        \
      printf("\n");                                                            \
    }                                                                          \
  } while (0)

/**
 * Convenience function to extract a prefix address from a buffer that uses
 * variable length encoding
 *
 * @param pfx_len       Number of bits in the prefix mask
 * @param dst           Buffer to write decoded prefix into (MUST be at least 4
 *                      bytes for IPv4 prefixes, and at least 16 bytes for IPv6
 *                      prefixes)
 * @param buf           Buffer to read the prefix from
 * @param buf_len       Total length of the buffer (to prevent overrun). Updated
 *                      to the number of bytes read from the buffer if
 *                      successful.
 * @return PARSEBGP_OK if successful, or an error code otherwise. buf_len is
 * only updated if PARSEBGP_OK is returned.
 */
parsebgp_error_t parsebgp_decode_prefix(uint8_t pfx_len, uint8_t *dst,
                                        uint8_t *buf, size_t *buf_len);

/** Convenience function to allocate and zero memory */
void *malloc_zero(const size_t size);

#endif /*  __PARSEBGP_UTILS_H */
