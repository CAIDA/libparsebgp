/*
 * Copyright (C) 2017 The Regents of the University of California.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PARSEBGP_UTILS_H
#define __PARSEBGP_UTILS_H

#include "parsebgp_error.h"
#include "config.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
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

/* Convert a network-order 16 bit integer pointed to by p to host order.
 * Safe even if value is unaligned, unlike ntohs(*(uint16_t*)p). */
#define nptohs(p)                                                              \
  ((uint16_t)                                                                  \
  (((uint16_t)((const uint8_t*)(p))[0] << 8) |                                 \
   ((uint16_t)((const uint8_t*)(p))[1])))

/* Convert a network-order 32 bit integer pointed to by p to host order.
 * Safe even if value is unaligned, unlike ntohl(*(uint32_t*)p). */
#define nptohl(p)                                                              \
  ((uint32_t)                                                                  \
  (((uint32_t)((const uint8_t*)(p))[0] << 24) |                                \
   ((uint32_t)((const uint8_t*)(p))[1] << 16) |                                \
   ((uint32_t)((const uint8_t*)(p))[2] << 8) |                                 \
   ((uint32_t)((const uint8_t*)(p))[3])))

/* Convert a network-order 64 bit integer pointed to by p to host order.
 * Safe even if value is unaligned, unlike ntohll(*(uint64_t*)p). */
#define nptohll(p)                                                             \
  ((uint64_t)                                                                  \
  (((uint64_t)((const uint8_t*)(p))[0] << 56) |                                \
   ((uint64_t)((const uint8_t*)(p))[1] << 48) |                                \
   ((uint64_t)((const uint8_t*)(p))[2] << 40) |                                \
   ((uint64_t)((const uint8_t*)(p))[3] << 32) |                                \
   ((uint64_t)((const uint8_t*)(p))[4] << 24) |                                \
   ((uint64_t)((const uint8_t*)(p))[5] << 16) |                                \
   ((uint64_t)((const uint8_t*)(p))[6] << 8) |                                 \
   ((uint64_t)((const uint8_t*)(p))[7])))

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
  PARSEBGP_DESERIALIZE_BYTES(buf, len, read, &(to), sizeof(to))

/** Convenience macros to deserialize a network-order integer from a byte array.
 * (They're also faster than PARSEBGP_DESERIALIZE_VAL() followed by ntoh*(),
 * and allow storing a value into a variable of a different size.)
 *
 * @param buf           pointer to the buffer (will be updated)
 * @param len           total length of the buffer
 * @param read          the number of bytes already read from the buffer
 *                      (will be updated)
 * @param to            the variable to deserialize into
 */
#define PARSEBGP_DESERIALIZE_UINT8(buf, len, read, to)                         \
  PARSEBGP_DESERIALIZE_INT_HELPER(buf, len, read, to, uint8_t, *(const uint8_t*))

#define PARSEBGP_DESERIALIZE_UINT16(buf, len, read, to)                        \
  PARSEBGP_DESERIALIZE_INT_HELPER(buf, len, read, to, uint16_t, nptohs)

#define PARSEBGP_DESERIALIZE_UINT32(buf, len, read, to)                        \
  PARSEBGP_DESERIALIZE_INT_HELPER(buf, len, read, to, uint32_t, nptohl)

#define PARSEBGP_DESERIALIZE_UINT64(buf, len, read, to)                        \
  PARSEBGP_DESERIALIZE_INT_HELPER(buf, len, read, to, uint64_t, nptohll)

#define PARSEBGP_DESERIALIZE_INT_HELPER(buf, len, read, to, type, getval)      \
  do {                                                                         \
    /* static_assert(sizeof(to) == sizeof(type), "size mismatch"); */          \
    assert((len) >= (read));                                                   \
    if (((len) - (read)) < sizeof(type)) {                                     \
      return PARSEBGP_PARTIAL_MSG;                                             \
    }                                                                          \
    to = getval(buf);                                                          \
    read += sizeof(type);                                                      \
    buf += sizeof(type);                                                       \
  } while (0)

/** Convenience macro to deserialize raw bytes from a byte array.
 *
 * @param buf           pointer to the buffer (will be updated)
 * @param len           total length of the buffer
 * @param read          the number of bytes already read from the buffer
 *                      (will be updated)
 * @param ptr           pointer to memory to deserialize into
 * @param n             number of bytes to deserialize
 */
#define PARSEBGP_DESERIALIZE_BYTES(buf, len, read, ptr, n)                     \
  do {                                                                         \
    assert((len) >= (read));                                                   \
    if (((len) - (read)) < (n)) {                                              \
      return PARSEBGP_PARTIAL_MSG;                                             \
    }                                                                          \
    memcpy((ptr), (buf), (n));                                                 \
    read += (n);                                                               \
    buf += (n);                                                                \
  } while (0)


/** Convenience macro to either abort parsing or skip an unimplemented feature
    depending on run-time configuration */
#define PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain, msg_fmt, ...)  \
  do {                                                                         \
    if ((opts)->ignore_not_implemented) {                                      \
      nread += (remain);                                                       \
      buf += (remain);                                                         \
      if (!(opts)->silence_not_implemented) {                                  \
        fprintf(stderr, "WARN: NOT_IMPLEMENTED: " msg_fmt " (%s:%d)\n",        \
                __VA_ARGS__, __FILE__, __LINE__);                              \
      }                                                                        \
    } else {                                                                   \
      fprintf(stderr, "ERROR: NOT_IMPLEMENTED: " msg_fmt " (%s:%d)\n",         \
              __VA_ARGS__, __FILE__, __LINE__);                                \
      return PARSEBGP_NOT_IMPLEMENTED;                                         \
    }                                                                          \
  } while (0)

/** Convenience macro to either abort parsing or skip a malformed feature (e.g.,
    path attribute) depending on run-time configuration */
#define PARSEBGP_SKIP_INVALID_MSG(opts, buf, nread, remain, msg_fmt, ...)      \
  do {                                                                         \
    if ((opts)->ignore_invalid) {                                              \
      nread += (remain);                                                       \
      buf += (remain);                                                         \
      if (!(opts)->silence_invalid) {                                          \
        fprintf(stderr, "WARN: INVALID_MSG: " msg_fmt " (%s:%d)\n",            \
                __VA_ARGS__, __FILE__, __LINE__);                              \
      }                                                                        \
    } else {                                                                   \
      fprintf(stderr, "ERROR: INVALID_MSG: " msg_fmt " (%s:%d)\n",             \
              __VA_ARGS__, __FILE__, __LINE__);                                \
      return PARSEBGP_INVALID_MSG;                                             \
    }                                                                          \
  } while (0)

#ifdef PARSER_DEBUG
#define PARSEBGP_RETURN_INVALID_MSG_ERR                                        \
  do {                                                                         \
    fprintf(stderr, "ERROR: INVALID_MSG at %s:%d\n", __FILE__, __LINE__);      \
    return PARSEBGP_INVALID_MSG;                                               \
  } while (0)
#else
#define PARSEBGP_RETURN_INVALID_MSG_ERR return PARSEBGP_INVALID_MSG
#endif

#define PARSEBGP_ASSERT(condition)                                             \
  do {                                                                         \
    if (!(condition)) {                                                        \
      PARSEBGP_RETURN_INVALID_MSG_ERR;                                         \
    }                                                                          \
  } while (0)


#define PARSEBGP_DUMP_STRUCT_HDR(struct_name, depth)                           \
  do {                                                                         \
    int _i;                                                                    \
    for (_i = 0; _i < (depth); _i++) {                                         \
      if (_i == depth - 1) {                                                   \
        fputs(" ", stdout);                                                    \
      } else {                                                                 \
        fputs("  ", stdout);                                                   \
      }                                                                        \
    }                                                                          \
    printf(">> " STR(struct_name) " (%ld bytes):\n", sizeof(struct_name));     \
  } while (0)

#define PARSEBGP_DUMP_INFO(depth, ...)                                         \
  do {                                                                         \
    int _i;                                                                    \
    fputs(" ", stdout);                                                        \
    for (_i = 0; _i < (depth); _i++) {                                         \
      fputs("  ", stdout);                                                     \
    }                                                                          \
    printf(__VA_ARGS__);                                                       \
  } while (0)

#if defined(__GNUC__)
 #define UNUSED  __attribute__((unused))
#else
 #define UNUSED  /* empty */
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
 #define STATIC_ASSERT(cond, msg) _Static_assert((cond), #msg)
#else
 #define STATIC_ASSERT(cond, msg) typedef char msg [(cond)?1:-1] UNUSED
#endif

#define PARSEBGP_DUMP_INT(depth, name, val)                                    \
  do {                                                                         \
    STATIC_ASSERT(sizeof(val) <= sizeof(int), val_is_larger_than_int);         \
    PARSEBGP_DUMP_INFO(depth, name ": %*d\n", 20 - (int)sizeof(name ":"),      \
                       (int)val);                                              \
  } while (0)

#define PARSEBGP_DUMP_VAL(depth, name, fmt, val)                               \
  PARSEBGP_DUMP_INFO(depth, name ": %*" fmt "\n",                              \
                     20 - (int)sizeof(name ":"), val)

#define PARSEBGP_DUMP_IP(depth, name, afi, ipaddr)                             \
  do {                                                                         \
    int mapping[] = {-1, AF_INET, AF_INET6};                                   \
    char ip_buf[INET6_ADDRSTRLEN] = "[invalid IP]";                            \
    inet_ntop(mapping[afi], ipaddr, ip_buf, INET6_ADDRSTRLEN);                 \
    PARSEBGP_DUMP_INFO(depth, name ": %*s\n", 20 - (int)sizeof(name ":"),      \
                       ip_buf);                                                \
  } while (0)

#define PARSEBGP_DUMP_PFX(depth, name, afi, ipaddr, len)                       \
  do {                                                                         \
    int mapping[] = {-1, AF_INET, AF_INET6};                                   \
    char ip_buf[INET6_ADDRSTRLEN] = "[invalid IP]";                            \
    inet_ntop(mapping[afi], ipaddr, ip_buf, INET6_ADDRSTRLEN);                 \
    PARSEBGP_DUMP_INFO(depth, name ": %*s/%d\n", 20 - (int)sizeof(name ":"),   \
                       ip_buf, len);                                           \
  } while (0)

#define PARSEBGP_DUMP_DATA(depth, name, data, len)                             \
  do {                                                                         \
    int _byte;                                                                 \
    PARSEBGP_DUMP_INFO(depth, name ": ");                                      \
    if ((len) == 0) {                                                          \
      fputs("NONE\n", stdout);                                                 \
    } else {                                                                   \
      for (_byte = 0; _byte < (len); _byte++) {                                \
        if (_byte != 0) {                                                      \
          fputs(" ", stdout);                                                  \
        }                                                                      \
        printf("%02X", (data)[_byte]);                                         \
      }                                                                        \
      fputs("\n", stdout);                                                     \
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
 * @param max_pfx_len   Maximum allowed pfx_len (32 for IPv4, 128 for IPv6)
 * @return PARSEBGP_OK if successful, or an error code otherwise. buf_len is
 * only updated if PARSEBGP_OK is returned.
 */
parsebgp_error_t parsebgp_decode_prefix(uint8_t pfx_len, uint8_t *dst,
                                        const uint8_t *buf, size_t *buf_len,
                                        size_t max_pfx_len);

/** Convenience function to allocate and zero memory */
void *malloc_zero(const size_t size);

/** Conditionally reallocate memory if not enough is currently allocated.
 *
 * Note: Relies on the type of ptr to determine the correct size to allocate.
 */
#define PARSEBGP_MAYBE_REALLOC(ptr, alloc_len, len)                            \
  do {                                                                         \
    if ((alloc_len) < (len)) {                                                 \
      if (((ptr) = realloc((ptr), sizeof(*(ptr)) * (len))) == NULL) {          \
        return PARSEBGP_MALLOC_FAILURE;                                        \
      }                                                                        \
      memset(ptr + alloc_len, 0, sizeof(*(ptr)) * ((len) - (alloc_len)));      \
      alloc_len = len;                                                         \
    }                                                                          \
  } while (0)

#define PARSEBGP_MAYBE_MALLOC_ZERO(ptr)                                        \
  do {                                                                         \
    if ((ptr) == NULL && ((ptr) = malloc_zero(sizeof(*(ptr)))) == NULL) {      \
      return PARSEBGP_MALLOC_FAILURE;                                          \
    }                                                                          \
  } while (0)

#endif /*  __PARSEBGP_UTILS_H */
