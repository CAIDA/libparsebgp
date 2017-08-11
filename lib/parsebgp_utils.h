#ifndef __PARSEBGP_UTILS_H
#define __PARSEBGP_UTILS_H

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

/** Internal to the STR macro */
#define XSTR(a) #a

/** Stringify a macro value */
#define STR(a) XSTR(a)

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
      fprintf(stderr, "DEBUG: Failed to extract %s (%s:%s)\n", STR(to),        \
              __FILE__, __func__);                                             \
      return INCOMPLETE_MSG;                                                   \
    }                                                                          \
    memcpy(&(to), (buf), sizeof(to));                                          \
    read += sizeof(to);                                                        \
    buf += sizeof(to);                                                         \
  } while (0)

// deprecated
ssize_t extract_from_buffer(uint8_t **buffer, int *buf_len, void *output_buf,
                            ssize_t output_len);

/**
 *  Simple function to swap bytes around from network to host or
 *  host to networking.  This method will convert any size byte variable,
 *  unlike ntohs and ntohl.
 *
 * @param [in/out] var   Variable containing data to update
 * @param [in]     size  Size of var - Default is size of var
 */
void SWAP_BYTES(void *var, int size);

/** Convenience function to allocate and zero memory */
void *malloc_zero(const size_t size);

#endif /*  __PARSEBGP_UTILS_H */
