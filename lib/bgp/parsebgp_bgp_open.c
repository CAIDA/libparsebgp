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

#include "parsebgp_bgp_open.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static parsebgp_error_t parse_capabilities(parsebgp_opts_t *opts,
                                           parsebgp_bgp_open_t *msg,
                                           uint8_t *buf, size_t *lenp,
                                           size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bgp_open_capability_t *cap;

  while ((remain - nread) > 0) {

    PARSEBGP_MAYBE_REALLOC(
      msg->capabilities, sizeof(parsebgp_bgp_open_capability_t),
      msg->_capabilities_alloc_cnt, msg->capabilities_cnt + 1);
    cap = &msg->capabilities[msg->capabilities_cnt++];

    // Code
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->code);

    // Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->len);

    // process data based on the code
    switch (cap->code) {

    case PARSEBGP_BGP_OPEN_CAPABILITY_MPBGP:
      if (cap->len != 4) {
        PARSEBGP_SKIP_INVALID_MSG(
          opts, buf, nread, cap->len,
          "Unexpected MPBGP OPEN Capability length (%d), expecting 4 bytes",
          cap->len);
        continue;
      }
      // AFI
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.mpbgp.afi);
      cap->values.mpbgp.afi = ntohs(cap->values.mpbgp.afi);

      // Reserved
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.mpbgp.reserved);

      // SAFI
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.mpbgp.safi);
      break;

    case PARSEBGP_BGP_OPEN_CAPABILITY_AS4:
      if (cap->len != 4) {
        PARSEBGP_SKIP_INVALID_MSG(
          opts, buf, nread, cap->len,
          "Unexpected AS4 OPEN Capability length (%d), expecting 4 bytes",
          cap->len);
      }
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.asn);
      cap->values.asn = ntohl(cap->values.asn);
      break;

    // capabilities that we are explicitly ignoring (since OpenBMP is ignoring
    // them)
    // TODO: either implement parsers for these, or just provide the raw data
    case PARSEBGP_BGP_OPEN_CAPABILITY_OUTBOUND_FILTER:
    case PARSEBGP_BGP_OPEN_CAPABILITY_GRACEFUL_RESTART:
    case PARSEBGP_BGP_OPEN_CAPABILITY_MULTI_SESSION:
    case PARSEBGP_BGP_OPEN_CAPABILITY_LLGR:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_ENHANCED:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_OLD:
    default:
      PARSEBGP_SKIP_NOT_IMPLEMENTED(
        opts, buf, nread, cap->len,
        "OPEN Capability %d is either unknown or currently unsupported",
        cap->code);
      break;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t parse_params(parsebgp_opts_t *opts,
                                     parsebgp_bgp_open_t *msg, uint8_t *buf,
                                     size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;
  uint8_t u8;

  msg->capabilities_cnt = 0;

  while ((remain - nread) > 0) {
    // Ensure this is a capabilities parameter
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);
    if (u8 != 2) {
      PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                    "Unsupported BGP OPEN parameter type (%d). "
                                    "Only the Capabilities parameter (Type 2) "
                                    "is supported",
                                    u8);
    }

    // Capabilities Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);

    // parse this capabilities parameter
    slen = len - nread;
    if ((err = parse_capabilities(opts, msg, buf, &slen, u8)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t parsebgp_bgp_open_decode(parsebgp_opts_t *opts,
                                          parsebgp_bgp_open_t *msg,
                                          uint8_t *buf, size_t *lenp,
                                          size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Version
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->version);

  // ASN
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->asn);
  msg->asn = ntohs(msg->asn);

  // Hold Time
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->hold_time);
  msg->hold_time = ntohs(msg->hold_time);

  // BGP ID
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->bgp_id);

  // Parameters Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->param_len);

  // no params
  if (msg->param_len == 0) {
    *lenp = nread;
    return PARSEBGP_OK;
  }

  // Parse the capabilities
  slen = len - nread;
  if ((err = parse_params(opts, msg, buf, &slen, (remain - nread))) !=
      PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  if (nread != remain) {
    fprintf(stderr, "ERROR: Trailing data after OPEN Capabilities.\n");
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_open_destroy(parsebgp_bgp_open_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // we don't (currently) have any capabilities that use dynamic memory, so for
  // now just free the capabilities array
  free(msg->capabilities);

  free(msg);
}

void parsebgp_bgp_open_clear(parsebgp_bgp_open_t *msg)
{
  if (msg == NULL) {
    return;
  }

  msg->capabilities_cnt = 0;
}

void parsebgp_bgp_open_dump(parsebgp_bgp_open_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_open_t, depth);

  PARSEBGP_DUMP_INT(depth, "Version", msg->version);
  PARSEBGP_DUMP_INT(depth, "ASN", msg->asn);
  PARSEBGP_DUMP_INT(depth, "Hold Time", msg->hold_time);
  PARSEBGP_DUMP_IP(depth, "BGP ID", PARSEBGP_BGP_AFI_IPV4, msg->bgp_id);
  PARSEBGP_DUMP_INT(depth, "Parameters Length", msg->param_len);
  PARSEBGP_DUMP_INT(depth, "Capabilities Count", msg->capabilities_cnt);
  depth++;
  int i;
  parsebgp_bgp_open_capability_t *cap;
  for (i = 0; i < msg->capabilities_cnt; i++) {
    cap = &msg->capabilities[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_open_capability_t, depth);

    PARSEBGP_DUMP_INT(depth, "Code", cap->code);
    PARSEBGP_DUMP_INT(depth, "Length", cap->len);

    depth++;
    switch (cap->code) {
    case PARSEBGP_BGP_OPEN_CAPABILITY_MPBGP:
      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_open_capability_mpbgp_t, depth);

      PARSEBGP_DUMP_INT(depth, "AFI", cap->values.mpbgp.afi);
      PARSEBGP_DUMP_INT(depth, "Reserved", cap->values.mpbgp.reserved);
      PARSEBGP_DUMP_INT(depth, "SAFI", cap->values.mpbgp.safi);
      break;

    case PARSEBGP_BGP_OPEN_CAPABILITY_AS4:
      PARSEBGP_DUMP_INT(depth, "AS4 ASN", cap->values.asn);
      break;

    // capabilities with data that we are ignoring (since OpenBMP is ignoring
    // it)
    case PARSEBGP_BGP_OPEN_CAPABILITY_OUTBOUND_FILTER:
    case PARSEBGP_BGP_OPEN_CAPABILITY_GRACEFUL_RESTART:
    case PARSEBGP_BGP_OPEN_CAPABILITY_MULTI_SESSION:
      PARSEBGP_DUMP_INFO(depth, "Note: Ignored Capability Data\n");
      break;

    // capabilities with no extra data:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_ENHANCED:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_OLD:
      break;

    default:
      break;
    }
    depth--;
  }
}
