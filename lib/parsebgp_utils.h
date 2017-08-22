#ifndef __PARSEBGP_UTILS_H
#define __PARSEBGP_UTILS_H

#include "parsebgp_error.h"
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

/** Internal to the STR macro */
#define XSTR(a) #a

/** Stringify a macro value */
#define STR(a) XSTR(a)

/* ntholl and htonll macros from
   http://www.codeproject.com/KB/cpp/endianness.aspx */
/** Byte-swap a 64-bit integer */
#ifndef ntohll
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) |	\
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
      return INCOMPLETE_MSG;                                                   \
    }                                                                          \
    memcpy(&(to), (buf), sizeof(to));                                          \
    read += sizeof(to);                                                        \
    buf += sizeof(to);                                                         \
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
 * @return PARSEBGP_OK if successful, or an error code otherwise. buf_len is only updated
 * if PARSEBGP_OK is returned.
 */
parsebgp_error_t parsebgp_decode_prefix(uint8_t pfx_len, uint8_t *dst,
                                        uint8_t *buf, size_t *buf_len);

/** Convenience function to allocate and zero memory */
void *malloc_zero(const size_t size);

#endif /*  __PARSEBGP_UTILS_H */
