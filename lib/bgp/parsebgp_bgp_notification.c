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

#include "parsebgp_bgp_notification.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

parsebgp_error_t
parsebgp_bgp_notification_decode(parsebgp_opts_t *opts,
                                 parsebgp_bgp_notification_t *msg, uint8_t *buf,
                                 size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;

  // Error Code
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->code);

  // Error Subcode
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->subcode);

  // Data
  msg->data_len = remain - nread;
  if ((len - nread) < msg->data_len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  PARSEBGP_MAYBE_REALLOC(msg->data, sizeof(uint8_t), msg->_data_alloc_len,
                         msg->data_len);
  memcpy(msg->data, buf, msg->data_len);
  nread += msg->data_len;

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_notification_destroy(parsebgp_bgp_notification_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->data);

  free(msg);
}

void parsebgp_bgp_notification_clear(parsebgp_bgp_notification_t *msg)
{
  msg->data_len = 0;
}

void parsebgp_bgp_notification_dump(parsebgp_bgp_notification_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_notification_t, depth);

  PARSEBGP_DUMP_INT(depth, "Error Code", msg->code);
  PARSEBGP_DUMP_INT(depth, "Error Subcode", msg->subcode);
  PARSEBGP_DUMP_INT(depth, "Data Length", msg->data_len);
  PARSEBGP_DUMP_DATA(depth, "Data", msg->data, msg->data_len);
}
