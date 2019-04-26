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

#include "parsebgp_bgp_update_mp_reach.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static parsebgp_error_t parse_afi_ipv4_ipv6_nlri(
  parsebgp_opts_t *opts, parsebgp_bgp_afi_t afi, parsebgp_bgp_safi_t safi,
  parsebgp_bgp_prefix_t **nlris, int *nlris_alloc_cnt, int *nlris_cnt,
  const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  uint8_t p_type = 0;
  parsebgp_bgp_prefix_t *tuple;
  parsebgp_error_t err;

  switch (afi) {
  case PARSEBGP_BGP_AFI_IPV4:
    switch (safi) {
    case PARSEBGP_BGP_SAFI_UNICAST:
      p_type = PARSEBGP_BGP_PREFIX_UNICAST_IPV4;
      break;

    case PARSEBGP_BGP_SAFI_MULTICAST:
      p_type = PARSEBGP_BGP_PREFIX_MULTICAST_IPV4;
      break;

    default:
      PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                    "Unsupported SAFI (%d)", safi);
    }
    break;

  case PARSEBGP_BGP_AFI_IPV6:
    switch (safi) {
    case PARSEBGP_BGP_SAFI_UNICAST:
      p_type = PARSEBGP_BGP_PREFIX_UNICAST_IPV6;
      break;

    case PARSEBGP_BGP_SAFI_MULTICAST:
      p_type = PARSEBGP_BGP_PREFIX_MULTICAST_IPV6;
      break;

    default:
      PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                    "Unsupported SAFI (%d)", safi);
    }
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported AFI (%d)", afi);
  }

  *nlris_cnt = 0;

  while ((remain - nread) > 0) {
    PARSEBGP_MAYBE_REALLOC(*nlris, sizeof(parsebgp_bgp_prefix_t),
                           *nlris_alloc_cnt, *nlris_cnt + 1);
    tuple = &(*nlris)[*nlris_cnt];
    (*nlris_cnt)++;

    tuple->type = p_type;
    tuple->afi = afi;
    tuple->safi = safi;

    // Read the prefix length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, tuple->len);

    // Prefix
    slen = len - nread;
    if ((err = parsebgp_decode_prefix(tuple->len, tuple->addr, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_next_hop_afi_ipv4_ipv6(parsebgp_bgp_update_mp_reach_t *msg, const uint8_t *buf,
                             size_t *lenp, size_t remain)
{
  size_t nread = 0;
  // size of the link-local address (zero if there isn't one)
  uint8_t first_len, second_len = 0;

  // WARN: this assumes that the caller has checked that the buffer is long
  // enough to read msg->next_hop_len bytes

  // sanity-check
  if ((msg->afi == PARSEBGP_BGP_AFI_IPV4 && msg->next_hop_len != 4) ||
      (msg->afi == PARSEBGP_BGP_AFI_IPV6 &&
       (msg->next_hop_len != 16 && msg->next_hop_len != 32))) {
    fprintf(stderr,
            "ERROR: Unexpected Next-Hop length of %d for AFI %" PRIu16 "\n",
            msg->next_hop_len, msg->afi);
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  // handle optional v6 link-local address
  if (msg->next_hop_len == 32) {
    first_len = 16;
    second_len = 16;
  } else {
    first_len = msg->next_hop_len;
  }

  // copy first (or only) next-hop address
  memcpy(msg->next_hop, buf, first_len);
  memset(msg->next_hop + first_len, 0, sizeof(msg->next_hop) - first_len);
  nread += first_len;
  buf += first_len;

  // maybe copy link-local address
  if (second_len > 0) {
    memcpy(msg->next_hop_ll, buf, second_len);
    memset(msg->next_hop_ll + second_len, 0,
           sizeof(msg->next_hop_ll) - second_len);
    nread += second_len;
    buf += second_len;
  } else {
    memset(msg->next_hop_ll, 0, sizeof(msg->next_hop_ll));
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_reach_afi_ipv4_ipv6(parsebgp_opts_t *opts,
                          parsebgp_bgp_update_mp_reach_t *msg, const uint8_t *buf,
                          size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  if ((remain - nread) < msg->next_hop_len) {
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }
  if ((len - nread) < msg->next_hop_len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  switch (msg->safi) {
  case PARSEBGP_BGP_SAFI_UNICAST:
  case PARSEBGP_BGP_SAFI_MULTICAST:
    slen = len - nread;
    if ((err = parse_next_hop_afi_ipv4_ipv6(msg, buf, &slen, remain - nread)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;

    if (opts->bgp.mp_reach_no_afi_safi_reserved) {
      msg->reserved = 0;
    } else {
      // Reserved (always zero, apparently)
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->reserved);
    }

    // Parse the NLRIs
    slen = len - nread;
    if ((err = parse_afi_ipv4_ipv6_nlri(
           opts, msg->afi, msg->safi, &msg->nlris, &msg->_nlris_alloc_cnt,
           &msg->nlris_cnt, buf, &slen, remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_SAFI_MPLS:
  // TODO: add support for MPLS SAFI
  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported SAFI (%d)", msg->safi);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_unreach_afi_ipv4_ipv6(parsebgp_opts_t *opts,
                            parsebgp_bgp_update_mp_unreach_t *msg, const uint8_t *buf,
                            size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  slen = len - nread;

  switch (msg->safi) {
  case PARSEBGP_BGP_SAFI_UNICAST:
  case PARSEBGP_BGP_SAFI_MULTICAST:
    // Parse the NLRIs
    if ((err = parse_afi_ipv4_ipv6_nlri(
           opts, msg->afi, msg->safi, &msg->withdrawn_nlris,
           &msg->_withdrawn_nlris_alloc_cnt, &msg->withdrawn_nlris_cnt, buf,
           &slen, remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_SAFI_MPLS:
  // TODO: add support for MPLS SAFI
  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported SAFI (%d)", msg->safi);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t
parsebgp_bgp_update_mp_reach_decode(parsebgp_opts_t *opts,
                                    parsebgp_bgp_update_mp_reach_t *msg,
                                    const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // MRT TABLE_DUMP_V2 is annoying and can "compress" the MP_REACH header to
  // remove AFI, SAFI, and (allegedly) reserved fields
  //
  // however, it seems that in practice this doesn't happen. we try to deal with
  // this special case by peeking at the first byte in the case that we're
  // processing MRT data, and if it is zero (i.e. would indicate a next-hop
  // length of zero if the header was compressed), then we assume that the
  // header is in fact not compressed and we toggle the flag off in the options.
  if (opts->bgp.mp_reach_no_afi_safi_reserved && *buf != 0) {
    msg->afi = opts->bgp.afi;
    msg->safi = opts->bgp.safi;
  } else {
    // force reading of "reserved" byte
    opts->bgp.mp_reach_no_afi_safi_reserved = 0;

    // AFI
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->afi);
    msg->afi = ntohs(msg->afi);

    // SAFI
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->safi);
  }

  // Next-Hop Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->next_hop_len);

  // process next-hop and NLRI based on AFI
  // these functions must also read the "reserved" field
  // TODO: support other AFIs (BGPLS etc.)
  switch (msg->afi) {
  case PARSEBGP_BGP_AFI_IPV4:
  case PARSEBGP_BGP_AFI_IPV6:
    slen = len - nread;
    if ((err = parse_reach_afi_ipv4_ipv6(opts, msg, buf, &slen,
                                         remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported AFI (%d)", msg->afi);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_mp_reach_destroy(parsebgp_bgp_update_mp_reach_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->nlris);
  free(msg);
}

void parsebgp_bgp_update_mp_reach_clear(parsebgp_bgp_update_mp_reach_t *msg)
{
  msg->nlris_cnt = 0;
}

void parsebgp_bgp_update_mp_reach_dump(parsebgp_bgp_update_mp_reach_t *msg,
                                       int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_mp_reach_t, depth);

  PARSEBGP_DUMP_INT(depth, "AFI", msg->afi);
  PARSEBGP_DUMP_INT(depth, "SAFI", msg->safi);
  PARSEBGP_DUMP_INT(depth, "Next Hop Length", msg->next_hop_len);

  if (msg->safi != PARSEBGP_BGP_SAFI_UNICAST &&
      msg->safi != PARSEBGP_BGP_SAFI_MULTICAST) {
    PARSEBGP_DUMP_INFO(depth, "MP_REACH SAFI %d Not Supported\n", msg->safi);
    return;
  }

  switch (msg->afi) {
  case PARSEBGP_BGP_AFI_IPV4:
  case PARSEBGP_BGP_AFI_IPV6:
    PARSEBGP_DUMP_IP(depth, "Next Hop", msg->afi, msg->next_hop);
    if (msg->afi == PARSEBGP_BGP_AFI_IPV6 && msg->next_hop_len == 32) {
      PARSEBGP_DUMP_IP(depth, "Next Hop Link-Local", msg->afi,
                       msg->next_hop_ll);
    }

    PARSEBGP_DUMP_INT(depth, "Reserved", msg->reserved);
    PARSEBGP_DUMP_INT(depth, "NLRIs Count", msg->nlris_cnt);

    parsebgp_bgp_dump_prefixes(msg->nlris, msg->nlris_cnt, depth + 1);
    break;

  default:
    PARSEBGP_DUMP_INFO(depth, "MP_REACH AFI %d Not Supported\n", msg->afi);
    break;
  }
}

parsebgp_error_t
parsebgp_bgp_update_mp_unreach_decode(parsebgp_opts_t *opts,
                                      parsebgp_bgp_update_mp_unreach_t *msg,
                                      const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // AFI
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->afi);
  msg->afi = ntohs(msg->afi);

  // SAFI
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->safi);

  // process NLRIs based on AFI
  // TODO: support other AFIs (BGPLS etc.)
  switch (msg->afi) {
  case PARSEBGP_BGP_AFI_IPV4:
  case PARSEBGP_BGP_AFI_IPV6:
    slen = len - nread;
    if ((err = parse_unreach_afi_ipv4_ipv6(opts, msg, buf, &slen,
                                           remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported AFI (%d)", msg->afi);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_mp_unreach_destroy(
  parsebgp_bgp_update_mp_unreach_t *msg)
{
  if (msg == NULL) {
    return;
  }
  free(msg->withdrawn_nlris);
  free(msg);
}

void parsebgp_bgp_update_mp_unreach_clear(parsebgp_bgp_update_mp_unreach_t *msg)
{
  msg->withdrawn_nlris_cnt = 0;
}

void parsebgp_bgp_update_mp_unreach_dump(parsebgp_bgp_update_mp_unreach_t *msg,
                                         int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_mp_unreach_t, depth);

  PARSEBGP_DUMP_INT(depth, "AFI", msg->afi);
  PARSEBGP_DUMP_INT(depth, "SAFI", msg->safi);

  if (msg->safi != PARSEBGP_BGP_SAFI_UNICAST &&
      msg->safi != PARSEBGP_BGP_SAFI_MULTICAST) {
    PARSEBGP_DUMP_INFO(depth, "MP_UNREACH SAFI %d Not Supported\n", msg->safi);
    return;
  }

  switch (msg->afi) {
  case PARSEBGP_BGP_AFI_IPV4:
  case PARSEBGP_BGP_AFI_IPV6:
    PARSEBGP_DUMP_INT(depth, "Withdrawn NLRIs Count", msg->withdrawn_nlris_cnt);

    parsebgp_bgp_dump_prefixes(msg->withdrawn_nlris, msg->withdrawn_nlris_cnt,
                               depth + 1);
    break;

  default:
    PARSEBGP_DUMP_INFO(depth, "MP_UNREACH AFI %d Not Supported\n", msg->afi);
    break;
  }
}
