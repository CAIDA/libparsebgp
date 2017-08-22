//
// Created by Induja on 4/6/2017.
//

#include "parsebgp_utils.h"
#include "parsebgp.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

parsebgp_error_t parsebgp_decode_prefix(uint8_t pfx_len, uint8_t *dst,
                                        uint8_t *buf, size_t *buf_len)
{
  uint8_t bytes, junk;
  // prefixes are encoded in a compact format the min number of bytes is used,
  // so we first need to figure out how many bytes it takes to represent a
  // prefix of this length.
  // TODO: figure out how to get rid of the modulo
  bytes = pfx_len / 8;
  if ((junk = pfx_len % 8) != 0) {
    bytes++;
  }
  // now read the prefix
  if (*buf_len < bytes) {
    return INCOMPLETE_MSG;
  }
  memcpy(dst, buf, bytes);
  // technically the trailing bits can be anything, so zero them out just to be
  // helpful.
  if (junk != 0) {
    junk = 8 - junk;
    dst[bytes-1] = dst[bytes-1] & (0xFF << junk);
  }
  // and ensure the rest of the buffer is clean
  memset(dst + bytes, 0, 16 - bytes);

  *buf_len = bytes;
  return PARSEBGP_OK;
}

void *malloc_zero(const size_t size)
{
  return calloc(size, 1);
}
