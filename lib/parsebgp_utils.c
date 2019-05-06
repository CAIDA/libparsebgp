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

#include "parsebgp_utils.h"
#include "parsebgp.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

parsebgp_error_t parsebgp_decode_prefix(uint8_t pfx_len, uint8_t *dst,
                                        const uint8_t *buf, size_t *buf_len,
                                        size_t max_pfx_len)
{
  uint8_t bytes, junk;
  PARSEBGP_ASSERT(pfx_len <= max_pfx_len);
  // prefixes are encoded in a compact format the min number of bytes is used,
  // so we first need to figure out how many bytes it takes to represent a
  // prefix of this length.
  bytes = pfx_len / 8;
  if ((junk = (pfx_len % 8)) != 0) {
    bytes++;
  }
  // now read the prefix
  if (*buf_len < bytes) {
    return PARSEBGP_PARTIAL_MSG;
  }
  memcpy(dst, buf, bytes);
  // technically the trailing bits can be anything, so zero them out just to be
  // helpful.
  if (junk != 0) {
    junk = 8 - junk;
    dst[bytes - 1] = dst[bytes - 1] & (0xFF << junk);
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
