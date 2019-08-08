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

#include "parsebgp_bmp.h"
#include "parsebgp_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BMP_HDR_V1V2_LEN 43 ///< BMP v1/2 header length
#define BMP_HDR_V3_LEN 6    ///< BMP v3 header length
#define BMP_PEER_HDR_LEN 42 ///< BMP peer header length

/* -------------------- Helper parser functions -------------------- */

static parsebgp_error_t parse_info_tlvs(parsebgp_bmp_info_tlv_t **tlvs,
                                        int *tlvs_alloc_cnt, int *tlvs_cnt,
                                        const uint8_t *buf, size_t *lenp,
                                        size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bmp_info_tlv_t *tlv = NULL;

  assert(remain <= len);
  *tlvs_cnt = 0;

  // read and realloc tlvs until we run out of message
  while (remain > 0) {
    PARSEBGP_MAYBE_REALLOC(*tlvs, *tlvs_alloc_cnt, *tlvs_cnt + 1);
    tlv = &(*tlvs)[*tlvs_cnt];
    (*tlvs_cnt)++;

    // read the TLV header
    // Type
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->type);

    // Length
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->len);

    remain -= sizeof(tlv->type) + sizeof(tlv->len);

    // Info data
    PARSEBGP_ASSERT(tlv->len <= remain); // length field must match the common header
    PARSEBGP_MAYBE_REALLOC(tlv->info, tlv->_info_alloc_len, tlv->len);
    PARSEBGP_DESERIALIZE_BYTES(buf, len, nread, tlv->info, tlv->len);
    remain -= tlv->len;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_info_tlvs(parsebgp_bmp_info_tlv_t **tlvs,
                              int *tlvs_alloc_cnt)
{
  int i;
  if (*tlvs == NULL || *tlvs_alloc_cnt == 0) {
    return;
  }

  for (i = 0; i < *tlvs_alloc_cnt; i++) {
    free((*tlvs)[i].info);
    (*tlvs)[i].info = NULL;
  }
  free(*tlvs);
  *tlvs = NULL;
  *tlvs_alloc_cnt = 0;
}

static void clear_info_tlvs(parsebgp_bmp_info_tlv_t **tlvs, int *tlvs_cnt)
{
  int i;
  if (*tlvs_cnt == 0) {
    return;
  }

  for (i = 0; i < *tlvs_cnt; i++) {
    (*tlvs)[i].len = 0;
  }
  *tlvs_cnt = 0;
}

static void dump_info_tlvs(const parsebgp_bmp_info_tlv_t *tlvs, int tlvs_cnt,
                           int depth)
{
  int i;
  const parsebgp_bmp_info_tlv_t *tlv;

  for (i = 0; i < tlvs_cnt; i++) {
    tlv = &tlvs[i];
    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_info_tlv_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", tlv->type);
    PARSEBGP_DUMP_INT(depth, "Length", tlv->len);
    PARSEBGP_DUMP_INFO(depth, "Value: '%.*s'\n", tlv->len, tlv->info);
  }
}

/* -------------------- BMP Message Type Parsers -------------------- */

// Type 1:
static parsebgp_error_t parse_stats_report(parsebgp_opts_t *opts,
                                           parsebgp_bmp_stats_report_t *msg,
                                           const uint8_t *buf, size_t *lenp,
                                           size_t remain)
{
  size_t len = *lenp, nread = 0;
  uint64_t i;
  parsebgp_bmp_stats_counter_t *sc;

  // Stats Count
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->stats_count);

  // Allocate enough counter structures
  PARSEBGP_MAYBE_REALLOC(msg->counters,
                         msg->_counters_alloc_cnt, msg->stats_count);
  memset(msg->counters, 0,
         sizeof(parsebgp_bmp_stats_counter_t) * msg->stats_count);

  // parse each stat
  for (i = 0; i < msg->stats_count; i++) {
    sc = &msg->counters[i];

    // Type
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, sc->type);

    // Length
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, sc->len);

    PARSEBGP_ASSERT(sc->len <= remain - nread);

    // Read the data
    switch (sc->type) {
    // 32-bit counter types:
    case PARSEBGP_BMP_STATS_PREFIX_REJECTS:
    case PARSEBGP_BMP_STATS_PREFIX_DUPS:
    case PARSEBGP_BMP_STATS_WITHDRAW_DUP:
    case PARSEBGP_BMP_STATS_INVALID_CLUSTER_LIST:
    case PARSEBGP_BMP_STATS_INVALID_AS_PATH_LOOP:
    case PARSEBGP_BMP_STATS_INVALID_ORIGINATOR_ID:
    case PARSEBGP_BMP_STATS_INVALID_AS_CONFED_LOOP:
    case PARSEBGP_BMP_STATS_UPD_TREAT_AS_WITHDRAW:
    case PARSEBGP_BMP_STATS_PREFIX_TREAT_AS_WITHDRAW:
    case PARSEBGP_BMP_STATS_DUP_UPD:
      PARSEBGP_ASSERT(sc->len == sizeof(sc->data.counter_u32));
      PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, sc->data.counter_u32);
      break;

    // 64-bit gauge types:
    case PARSEBGP_BMP_STATS_ROUTES_ADJ_RIB_IN:
    case PARSEBGP_BMP_STATS_ROUTES_LOC_RIB:
      PARSEBGP_ASSERT(sc->len == sizeof(sc->data.gauge_u64));
      PARSEBGP_DESERIALIZE_UINT64(buf, len, nread, sc->data.gauge_u64);
      break;

    // AFI/SAFI 64-bit gauge types:
    case PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_ADJ_RIB_IN:
    case PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_LOC_RIB:
      PARSEBGP_ASSERT(sc->len == 11);

      // AFI
      PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, sc->data.afi_safi_gauge.afi);

      // SAFI
      PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, sc->data.afi_safi_gauge.safi);

      // u64 gauge
      PARSEBGP_DESERIALIZE_UINT64(buf, len, nread,
                               sc->data.afi_safi_gauge.gauge_u64);
      break;

    default:
      // pass remain==0 to macro since we'll try and parse ourselves
      PARSEBGP_SKIP_NOT_IMPLEMENTED(
        opts, buf, nread, 0, "Unknown BMP Stat Counter type (%d)", sc->type);
      // if we reach here, user wants us to struggle on
      if (sc->len == 8) {
        PARSEBGP_DESERIALIZE_UINT64(buf, len, nread, sc->data.gauge_u64);
      } else if (sc->len == 4) {
        PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, sc->data.counter_u32);
      } else {
        buf += sc->len;
        nread += sc->len;
      }
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_stats_report(parsebgp_bmp_stats_report_t *msg)
{
  if (msg == NULL) {
    return;
  }
  free(msg->counters);
  free(msg);
}

static void clear_stats_report(parsebgp_bmp_stats_report_t *msg)
{
  if (msg == NULL) {
    return;
  }
  msg->stats_count = 0;
}

static void dump_stats_report(const parsebgp_bmp_stats_report_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_stats_report_t, depth);

  PARSEBGP_DUMP_INT(depth, "Stats Count", msg->stats_count);

  depth++;
  parsebgp_bmp_stats_counter_t *sc;
  for (uint32_t i = 0; i < msg->stats_count; i++) {
    sc = &msg->counters[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_stats_counter_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", sc->type);
    PARSEBGP_DUMP_INT(depth, "Length", sc->len);

    switch (sc->type) {
    // 32-bit counter types:
    case PARSEBGP_BMP_STATS_PREFIX_REJECTS:
    case PARSEBGP_BMP_STATS_PREFIX_DUPS:
    case PARSEBGP_BMP_STATS_WITHDRAW_DUP:
    case PARSEBGP_BMP_STATS_INVALID_CLUSTER_LIST:
    case PARSEBGP_BMP_STATS_INVALID_AS_PATH_LOOP:
    case PARSEBGP_BMP_STATS_INVALID_ORIGINATOR_ID:
    case PARSEBGP_BMP_STATS_INVALID_AS_CONFED_LOOP:
    case PARSEBGP_BMP_STATS_UPD_TREAT_AS_WITHDRAW:
    case PARSEBGP_BMP_STATS_PREFIX_TREAT_AS_WITHDRAW:
    case PARSEBGP_BMP_STATS_DUP_UPD:
      PARSEBGP_DUMP_INT(depth, "u32", sc->data.counter_u32);
      break;

    // 64-bit gauge types:
    case PARSEBGP_BMP_STATS_ROUTES_ADJ_RIB_IN:
    case PARSEBGP_BMP_STATS_ROUTES_LOC_RIB:
      PARSEBGP_DUMP_VAL(depth, "u64", PRIu64, sc->data.gauge_u64);
      break;

    // AFI/SAFI 64-bit gauge types:
    case PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_ADJ_RIB_IN:
    case PARSEBGP_BMP_STATS_ROUTES_PER_AFI_SAFI_LOC_RIB:
      // AFI
      PARSEBGP_DUMP_INT(depth, "AFI", sc->data.afi_safi_gauge.afi);

      // SAFI
      PARSEBGP_DUMP_INT(depth, "SAFI", sc->data.afi_safi_gauge.safi);

      // u64 gauge
      PARSEBGP_DUMP_VAL(depth, "u64", PRIu64, sc->data.afi_safi_gauge.gauge_u64);
      break;

    default:
      if (sc->len == 4) {
        PARSEBGP_DUMP_INT(depth, "u32", sc->data.counter_u32);
      } else if (sc->len == 8) {
        PARSEBGP_DUMP_VAL(depth, "u64", PRIu64, sc->data.gauge_u64);
      }
    }
  }
}

// Type 2:
static parsebgp_error_t parse_peer_down(parsebgp_opts_t *opts,
                                        parsebgp_bmp_peer_down_t *msg,
                                        const uint8_t *buf, size_t *lenp,
                                        size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Reason
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->reason);

  // Read the data (if present)
  switch (msg->reason) {
  // Reasons with a BGP NOTIFICATION message
  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF:
  case PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->data.notification);
    slen = len - nread;
    if ((err = parsebgp_bgp_decode(opts, msg->data.notification, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE:
    // read the fsm code
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->data.fsm_code);
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported BMP Peer-Down Reason (%d)",
                                  msg->reason);
    break;
  }

  // did we read too much/little data according to the common header length?
  PARSEBGP_ASSERT(remain == nread);

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_peer_down(parsebgp_bmp_peer_down_t *msg)
{
  if (msg == NULL) {
    return;
  }
  parsebgp_bgp_destroy_msg(msg->data.notification);
  free(msg);
}

static void clear_peer_down(parsebgp_bmp_peer_down_t *msg)
{
  switch (msg->reason) {
  // Reasons with a BGP NOTIFICATION message
  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF:
  case PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF:
    parsebgp_bgp_clear_msg(msg->data.notification);
    break;

  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE:
  default:
    // nothing to do
    break;
  }
}

static void dump_peer_down(const parsebgp_bmp_peer_down_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_peer_down_t, depth);

  PARSEBGP_DUMP_INT(depth, "Reason", msg->reason);

  depth++;
  switch (msg->reason) {
  // Reasons with a BGP NOTIFICATION message
  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF:
  case PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF:
    parsebgp_bgp_dump_msg(msg->data.notification, depth);
    break;

  case PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE:
    PARSEBGP_DUMP_INT(depth, "FSM Code", msg->data.fsm_code);
    break;

  default:
    break;
  }
}

// Type 3:
static parsebgp_error_t parse_peer_up(parsebgp_opts_t *opts,
                                      parsebgp_bmp_peer_up_t *msg, const uint8_t *buf,
                                      size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // copy the AFI into the header for convenience
  msg->local_ip_afi = opts->bmp.peer_ip_afi;

  if (msg->local_ip_afi == PARSEBGP_BGP_AFI_IPV4) {
    if ((len - nread) < 16) {
      return PARSEBGP_PARTIAL_MSG;
    }
    // skip over the empty bytes
    nread += 12;
    buf += 12;
    // and read the v2 addr
    memcpy(msg->local_ip, buf, 4);
    nread += 4;
    buf += 4;
  } else {
    // IPv6, copy the full 16-bytes as-is
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->local_ip);
  }

  // Local port
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->local_port);

  // Remote port
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->remote_port);

  PARSEBGP_MAYBE_MALLOC_ZERO(msg->sent_open);
  slen = len - nread;
  if ((err = parsebgp_bgp_decode(opts, msg->sent_open, buf, &slen)) !=
      PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  PARSEBGP_MAYBE_MALLOC_ZERO(msg->recv_open);
  slen = len - nread;
  if ((err = parsebgp_bgp_decode(opts, msg->recv_open, buf, &slen)) !=
      PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  // Information TLVs (optional)
  parse_info_tlvs(&msg->tlvs, &msg->_tlvs_alloc_cnt, &msg->tlvs_cnt, buf, lenp,
                  remain - nread);

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_peer_up(parsebgp_bmp_peer_up_t *msg)
{
  if (msg == NULL) {
    return;
  }
  parsebgp_bgp_destroy_msg(msg->sent_open);
  parsebgp_bgp_destroy_msg(msg->recv_open);
  destroy_info_tlvs(&msg->tlvs, &msg->_tlvs_alloc_cnt);
  free(msg);
}

static void clear_peer_up(parsebgp_bmp_peer_up_t *msg)
{
  parsebgp_bgp_clear_msg(msg->sent_open);
  parsebgp_bgp_clear_msg(msg->recv_open);
  clear_info_tlvs(&msg->tlvs, &msg->tlvs_cnt);
}

static void dump_peer_up(const parsebgp_bmp_peer_up_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_peer_up_t, depth);

  PARSEBGP_DUMP_IP(depth, "Local IP", msg->local_ip_afi, msg->local_ip);
  PARSEBGP_DUMP_INT(depth, "Local Port", msg->local_port);
  PARSEBGP_DUMP_INT(depth, "Remote Port", msg->remote_port);

  PARSEBGP_DUMP_INFO(depth, "Sent OPEN:\n");
  parsebgp_bgp_dump_msg(msg->sent_open, depth + 1);

  PARSEBGP_DUMP_INFO(depth, "Received OPEN:\n");
  parsebgp_bgp_dump_msg(msg->recv_open, depth + 1);

  PARSEBGP_DUMP_INT(depth, "TLVs Count", msg->tlvs_cnt);

  if (msg->tlvs_cnt > 0) {
    dump_info_tlvs(msg->tlvs, msg->tlvs_cnt, depth + 1);
  }
}

// Type 4:
static parsebgp_error_t parse_init_msg(parsebgp_bmp_init_msg_t *msg,
                                       const uint8_t *buf, size_t *lenp,
                                       size_t remain)
{
  return parse_info_tlvs(&msg->tlvs, &msg->_tlvs_alloc_cnt, &msg->tlvs_cnt, buf,
                         lenp, remain);
}

static void destroy_init_msg(parsebgp_bmp_init_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }
  destroy_info_tlvs(&msg->tlvs, &msg->_tlvs_alloc_cnt);
  free(msg);
}

static void clear_init_msg(parsebgp_bmp_init_msg_t *msg)
{
  clear_info_tlvs(&msg->tlvs, &msg->tlvs_cnt);
}

static void dump_init_msg(const parsebgp_bmp_init_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_init_msg_t, depth);

  PARSEBGP_DUMP_INT(depth, "TLV Count", msg->tlvs_cnt);
  dump_info_tlvs(msg->tlvs, msg->tlvs_cnt, depth + 1);
}

// Type 5:
static parsebgp_error_t parse_term_msg(parsebgp_bmp_term_msg_t *msg,
                                       const uint8_t *buf, size_t *lenp,
                                       size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bmp_term_tlv_t *tlv = NULL;

  msg->tlvs_cnt = 0;

  // read until we run out of message
  while (remain > 0) {
    PARSEBGP_MAYBE_REALLOC(msg->tlvs, msg->_tlvs_alloc_cnt, msg->tlvs_cnt + 1);
    tlv = &msg->tlvs[msg->tlvs_cnt];
    msg->tlvs_cnt++;

    // read the TLV header
    // Type
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->type);

    // Length
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->len);

    remain -= sizeof(tlv->type) + sizeof(tlv->len);

    // does length field agree with common header?
    PARSEBGP_ASSERT(tlv->len <= remain);

    // parse the info based on the type
    switch (tlv->type) {
    case PARSEBGP_BMP_TERM_INFO_TYPE_STRING:
      // allocate a string buffer for the data
      PARSEBGP_MAYBE_REALLOC(tlv->info.string,
                             tlv->info._string_alloc_len, tlv->len + 1);
      // and then copy it in
      PARSEBGP_DESERIALIZE_BYTES(buf, len, nread, tlv->info.string, tlv->len);
      tlv->info.string[tlv->len] = '\0';
      break;

    case PARSEBGP_BMP_TERM_INFO_TYPE_REASON:
      PARSEBGP_ASSERT(tlv->len == 2);
      PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->info.reason);
      break;

    default:
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }
    remain -= tlv->len;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_term_msg(parsebgp_bmp_term_msg_t *msg)
{
  int i;
  if (msg == NULL || msg->_tlvs_alloc_cnt == 0) {
    return;
  }

  for (i = 0; i < msg->_tlvs_alloc_cnt; i++) {
    free(msg->tlvs[i].info.string);
    msg->tlvs[i].info.string = NULL;
  }
  free(msg->tlvs);
  msg->tlvs = NULL;
  msg->_tlvs_alloc_cnt = 0;
  free(msg);
}

static void clear_term_msg(parsebgp_bmp_term_msg_t *msg)
{
  int i;
  if (msg->tlvs_cnt == 0) {
    return;
  }

  for (i = 0; i < msg->tlvs_cnt; i++) {
    msg->tlvs[i].len = 0;
  }
  msg->tlvs_cnt = 0;
}

static void dump_term_msg(const parsebgp_bmp_term_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_term_msg_t, depth);

  PARSEBGP_DUMP_INT(depth, "TLV Count", msg->tlvs_cnt);

  depth++;
  int i;
  parsebgp_bmp_term_tlv_t *tlv;
  for (i = 0; i < msg->tlvs_cnt; i++) {
    tlv = &msg->tlvs[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_term_tlv_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", tlv->type);
    PARSEBGP_DUMP_INT(depth, "Length", tlv->len);

    switch (tlv->type) {
    case PARSEBGP_BMP_TERM_INFO_TYPE_STRING:
      PARSEBGP_DUMP_INFO(depth, "String: '%s'\n", tlv->info.string);
      break;

    case PARSEBGP_BMP_TERM_INFO_TYPE_REASON:
      PARSEBGP_DUMP_INT(depth, "Reason", tlv->info.reason);
      break;

    default:
      break;
    }
  }
}

// Type 6:
static parsebgp_error_t parse_route_mirror_msg(parsebgp_opts_t *opts,
                                               parsebgp_bmp_route_mirror_t *msg,
                                               const uint8_t *buf, size_t *lenp,
                                               size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_bmp_route_mirror_tlv_t *tlv = NULL;
  parsebgp_error_t err;

  // TODO: correctly configure the BGP parser for 4-byte ASes etc.  for now,
  // assume that the peer is 4-byte capable. maybe consider adding code to the
  // BGP parser to fall back to 2-byte parsing if the 4-byte parser fails.
  opts->bgp.asn_4_byte = 1;

  msg->tlvs_cnt = 0;

  // read tlvs until we run out of message
  while ((remain - nread) > 0) {
    PARSEBGP_MAYBE_REALLOC(msg->tlvs, msg->_tlvs_alloc_cnt, msg->tlvs_cnt + 1);
    tlv = &msg->tlvs[msg->tlvs_cnt];
    memset(tlv, 0, sizeof(*tlv));
    msg->tlvs_cnt++;

    // read the TLV header

    // Type
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->type);

    // Length
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->len);

    // does the length field agree with the common header?
    PARSEBGP_ASSERT(tlv->len <= (remain - nread));
    if (tlv->len > (len - nread)) {
      return PARSEBGP_PARTIAL_MSG;
    }

    // parse the info based on the type
    switch (tlv->type) {
    case PARSEBGP_BMP_ROUTE_MIRROR_TYPE_BGP_MSG:
      // parse the BGP message
      PARSEBGP_MAYBE_MALLOC_ZERO(tlv->values.bgp_msg);
      slen = len - nread;
      if ((err = parsebgp_bgp_decode(opts, tlv->values.bgp_msg, buf, &slen)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    case PARSEBGP_BMP_ROUTE_MIRROR_TYPE_INFO:
      PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, tlv->values.code);
      break;

    default:
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_route_mirror_msg(parsebgp_bmp_route_mirror_t *msg)
{
  int i;
  if (msg == NULL || msg->tlvs_cnt == 0) {
    return;
  }

  for (i = 0; i < msg->tlvs_cnt; i++) {
    parsebgp_bgp_destroy_msg(msg->tlvs[i].values.bgp_msg);
  }

  free(msg->tlvs);
  msg->tlvs = NULL;
  msg->_tlvs_alloc_cnt = 0;
  free(msg);
}

static void clear_route_mirror_msg(parsebgp_bmp_route_mirror_t *msg)
{
  int i;
  if (msg->tlvs_cnt == 0) {
    return;
  }

  for (i = 0; i < msg->tlvs_cnt; i++) {
    switch (msg->tlvs[i].type) {
    case PARSEBGP_BMP_ROUTE_MIRROR_TYPE_BGP_MSG:
      parsebgp_bgp_clear_msg(msg->tlvs[i].values.bgp_msg);
      break;

    case PARSEBGP_BMP_ROUTE_MIRROR_TYPE_INFO:
    default:
      // nothing to do
      break;
    }
  }

  msg->tlvs_cnt = 0;
}

static void dump_route_mirror_msg(const parsebgp_bmp_route_mirror_t *msg,
    int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_route_mirror_t, depth);

  PARSEBGP_DUMP_INT(depth, "TLVs Count", msg->tlvs_cnt);

  depth++;
  int i;
  parsebgp_bmp_route_mirror_tlv_t *tlv;

  for (i = 0; i < msg->tlvs_cnt; i++) {
    tlv = &msg->tlvs[i];
    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_route_mirror_tlv_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", tlv->type);
    PARSEBGP_DUMP_INT(depth, "Length", tlv->len);

    switch (tlv->type) {
    case PARSEBGP_BMP_ROUTE_MIRROR_TYPE_BGP_MSG:
      parsebgp_bgp_dump_msg(tlv->values.bgp_msg, depth + 1);
      break;

    case PARSEBGP_BMP_ROUTE_MIRROR_TYPE_INFO:
      PARSEBGP_DUMP_INT(depth, "Code", tlv->values.code);
      break;

    default:
      break;
    }
  }
}

/* -------------------- BMP Header Parsers -------------------- */

static parsebgp_error_t parse_peer_hdr(parsebgp_opts_t *opts,
                                       parsebgp_bmp_peer_hdr_t *hdr,
                                       const uint8_t *buf, size_t *lenp)
{
  size_t len = *lenp, nread = 0;

  // Type
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, hdr->type);

  // Flags
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, hdr->flags);

  // pass some of our flags back in the options so other parts of the parser can
  // use them
  if ((hdr->flags & PARSEBGP_BMP_PEER_FLAG_IPV6)) {
    hdr->afi = PARSEBGP_BGP_AFI_IPV6;
  } else {
    hdr->afi = PARSEBGP_BGP_AFI_IPV4;
  }
  opts->bmp.peer_ip_afi = hdr->afi;

  // Route distinguisher
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->dist_id);

  // IP Address
  //
  // BMP for some reason writes IPv4 addresses into the least-significant bytes,
  // meaning that it is stuck at [12, 13, 14, 15] in the hdr->addr byte array.
  // we need to rescue it
  if (hdr->afi == PARSEBGP_BGP_AFI_IPV4) {
    if ((len - nread) < 16) {
      return PARSEBGP_PARTIAL_MSG;
    }
    // skip over the empty bytes
    nread += 12;
    buf += 12;
    // and read the v2 addr
    memcpy(hdr->addr, buf, 4);
    nread += 4;
    buf += 4;
    // note that this will leave trailing garbage in the address, but you
    // weren't planning on reading more bytes than the peer flags suggests
    // anyway, right?
  } else {
    // IPv6, copy the full 16-bytes as-is
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->addr);
  }

  // AS Number
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, hdr->asn);

  // BGP ID
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, hdr->bgp_id);

  // Timestamp (seconds component)
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, hdr->ts_sec);

  // Timestamp (microseconds component)
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, hdr->ts_usec);

  assert(nread == BMP_PEER_HDR_LEN);
  *lenp = nread;
  return PARSEBGP_OK;
}

static void dump_peer_hdr(const parsebgp_bmp_peer_hdr_t *hdr, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_peer_hdr_t, depth);

  PARSEBGP_DUMP_INT(depth, "Type", hdr->type);
  PARSEBGP_DUMP_INT(depth, "Flags", hdr->flags);
  PARSEBGP_DUMP_VAL(depth, "Route Distinguisher", PRIu64, hdr->dist_id);
  int afi = (hdr->flags & PARSEBGP_BMP_PEER_FLAG_IPV6) ? PARSEBGP_BGP_AFI_IPV6
                                                       : PARSEBGP_BGP_AFI_IPV4;
  PARSEBGP_DUMP_IP(depth, "IP", afi, hdr->addr);
  PARSEBGP_DUMP_INT(depth, "ASN", hdr->asn);
  PARSEBGP_DUMP_IP(depth, "BGP ID", PARSEBGP_BGP_AFI_IPV4, hdr->bgp_id);

  PARSEBGP_DUMP_INT(depth, "Time.sec", hdr->ts_sec);
  PARSEBGP_DUMP_INT(depth, "Time.usec", hdr->ts_usec);
}

static parsebgp_error_t parse_common_hdr_v2(parsebgp_opts_t *opts,
                                            parsebgp_bmp_msg_t *msg,
                                            const uint8_t *buf, size_t *lenp)
{
  parsebgp_error_t err;
  size_t len = *lenp, nread = 0, slen = 0;
  uint16_t bgp_len;

  assert(msg->version == 2 || msg->version == 1);

  // Get the message type
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->type);

  // All v1/2 messages include the peer header
  slen = len;
  if ((err = parse_peer_hdr(opts, &msg->peer_hdr, buf, &slen)) != PARSEBGP_OK) {
    return err;
  }
  nread += slen;

  // Infer the overall message length by perhaps poking our nose into the next
  // message
  msg->len = nread;

  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:
    if (len - nread < 18) {
      return PARSEBGP_PARTIAL_MSG;
    }
    bgp_len = nptohs(buf + 16);
    msg->len += bgp_len;
    break;

  case PARSEBGP_BMP_TYPE_STATS_REPORT:
    // I'm not sure how to infer the length of this.
    // I'm not even sure how one would parse this data...
    fprintf(stderr,
            "ERROR: BMP v1/v2 Stats Report not supported. Cannot continue\n");
    return PARSEBGP_NOT_IMPLEMENTED;
    break;

  case PARSEBGP_BMP_TYPE_PEER_DOWN:
    if (len - nread < 1) {
      return PARSEBGP_PARTIAL_MSG;
    }
    if (*buf == PARSEBGP_BMP_PEER_DOWN_LOCAL_CLOSE_WITH_NOTIF ||
        *buf == PARSEBGP_BMP_PEER_DOWN_REMOTE_CLOSE_WITH_NOTIF) {
      if (len - nread < 19) {
        return PARSEBGP_PARTIAL_MSG;
      }
      bgp_len = nptohs(buf + 17);
      msg->len += bgp_len;
    }
    break;

  case PARSEBGP_BMP_TYPE_PEER_UP:
    // TODO: If this is actually found in the wild, then we can implement it
    fprintf(stderr,
            "ERROR: BMP v1/v2 Peer-Up not supported. Cannot continue\n");
    return PARSEBGP_NOT_IMPLEMENTED;
    break;
  }

  assert(nread == BMP_HDR_V1V2_LEN);
  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t parse_common_hdr_v3(parsebgp_opts_t *opts,
                                            parsebgp_bmp_msg_t *msg,
                                            const uint8_t *buf, size_t *lenp)
{
  parsebgp_error_t err;
  size_t len = *lenp, nread = 0;
  size_t slen;
  size_t bmplen = 0;

  // We know the version...
  assert(msg->version == 3);

  // Get the message length (including headers)
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->len);

  // Get the message type
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->type);

  // do quick sanity check on the message length
  bmplen = msg->len - BMP_HDR_V3_LEN;
  if (bmplen > len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  // parse the per-peer header for those message that contain it
  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:    // Route monitoring
  case PARSEBGP_BMP_TYPE_STATS_REPORT: // Statistics Report
  case PARSEBGP_BMP_TYPE_PEER_UP:      // Peer Up notification
  case PARSEBGP_BMP_TYPE_PEER_DOWN:    // Peer down notification
    slen = len;
    if ((err = parse_peer_hdr(opts, &msg->peer_hdr, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
  case PARSEBGP_BMP_TYPE_TERM_MSG:
    // no peer header
    break;

  default:
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t parse_common_hdr(parsebgp_opts_t *opts,
                                         parsebgp_bmp_msg_t *msg, const uint8_t *buf,
                                         size_t *lenp)
{
  parsebgp_error_t err;
  size_t len = *lenp, nread = 0;
  size_t slen;

  // Get the message version
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->version);

  switch (msg->version) {
  case 1:
  // Versions 1 and 2 use the same format, but v2 adds the Peer Up message
  case 2:
    slen = len - nread;
    if ((err = parse_common_hdr_v2(opts, msg, buf, &slen)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    break;

  case 3:
    slen = len - nread;
    if ((err = parse_common_hdr_v3(opts, msg, buf, &slen)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    break;

  default:
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void dump_common_hdr(const parsebgp_bmp_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_INT(depth, "Version", msg->version);
  PARSEBGP_DUMP_INT(depth, "Length", msg->len);
  PARSEBGP_DUMP_INT(depth, "Type", msg->type);

  if (msg->type == PARSEBGP_BMP_TYPE_INIT_MSG ||
      msg->type == PARSEBGP_BMP_TYPE_TERM_MSG) {
    return;
  }

  dump_peer_hdr(&msg->peer_hdr, depth + 1);
}

/* -------------------- Main BMP Parser ----------------------------- */

parsebgp_error_t parsebgp_bmp_decode(parsebgp_opts_t *opts,
                                     parsebgp_bmp_msg_t *msg, const uint8_t *buf,
                                     size_t *len)
{
  parsebgp_error_t err;
  size_t slen = 0, nread = 0, remain = 0;

  /* First, parse the message header */
  slen = *len;
  if ((err = parse_common_hdr(opts, msg, buf, &slen)) != PARSEBGP_OK) {
    return err;
  }
  nread += slen;

  /* Continue to parse the message based on the type */
  slen = *len - nread;       // number of bytes left in the buffer
  remain = msg->len - nread; // number of bytes left in the message

  if (opts->bmp.parse_headers_only) {
    msg->types_valid = 0;
    *len = msg->len;
    return PARSEBGP_OK;
  }
  msg->types_valid = 1;

  if (remain > slen) {
    // we already know that the message will be longer than what we have in the
    // buffer, give up now
    return PARSEBGP_PARTIAL_MSG;
  }

  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:
    // TODO: understand if it is sufficient to believe this flag
    opts->bgp.asn_4_byte =
      !(msg->peer_hdr.flags & PARSEBGP_BMP_PEER_FLAG_2_BYTE_AS_PATH);
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.route_mon);
    err = parsebgp_bgp_decode(opts, msg->types.route_mon, buf + nread, &slen);
    break;

  case PARSEBGP_BMP_TYPE_STATS_REPORT:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.stats_report);
    err = parse_stats_report(opts, msg->types.stats_report, buf + nread, &slen,
                             remain);
    break;

  case PARSEBGP_BMP_TYPE_PEER_DOWN:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.peer_down);
    err =
      parse_peer_down(opts, msg->types.peer_down, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_PEER_UP:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.peer_up);
    err = parse_peer_up(opts, msg->types.peer_up, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.init_msg);
    err = parse_init_msg(msg->types.init_msg, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_TERM_MSG:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.term_msg);
    err = parse_term_msg(msg->types.term_msg, buf + nread, &slen, remain);
    break;

  case PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.route_mirror);
    err = parse_route_mirror_msg(opts, msg->types.route_mirror, buf + nread,
                                 &slen, remain);
    break;
  }
  if (err != PARSEBGP_OK) {
    // parser failed
    return err;
  }
  nread += slen;

  assert(msg->len == nread);

  *len = nread;
  return PARSEBGP_OK;
}

void parsebgp_bmp_destroy_msg(parsebgp_bmp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // Common header has no dynamically allocated memory

  parsebgp_bgp_destroy_msg(msg->types.route_mon);
  destroy_stats_report(msg->types.stats_report);
  destroy_peer_down(msg->types.peer_down);
  destroy_peer_up(msg->types.peer_up);
  destroy_init_msg(msg->types.init_msg);
  destroy_term_msg(msg->types.term_msg);
  destroy_route_mirror_msg(msg->types.route_mirror);

  free(msg);
}

void parsebgp_bmp_clear_msg(parsebgp_bmp_msg_t *msg)
{
  // Common header has no dynamically allocated memory
  if (!msg->types_valid) {
    return;
  }

  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:
    parsebgp_bgp_clear_msg(msg->types.route_mon);
    break;

  case PARSEBGP_BMP_TYPE_STATS_REPORT:
    clear_stats_report(msg->types.stats_report);
    break;

  case PARSEBGP_BMP_TYPE_PEER_DOWN:
    clear_peer_down(msg->types.peer_down);
    break;

  case PARSEBGP_BMP_TYPE_PEER_UP:
    clear_peer_up(msg->types.peer_up);
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
    clear_init_msg(msg->types.init_msg);
    break;

  case PARSEBGP_BMP_TYPE_TERM_MSG:
    clear_term_msg(msg->types.term_msg);
    break;

  case PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG:
    clear_route_mirror_msg(msg->types.route_mirror);
    break;
  }
}

void parsebgp_bmp_dump_msg(const parsebgp_bmp_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bmp_msg_t, depth);

  dump_common_hdr(msg, depth);

  if (!msg->types_valid) {
    return;
  }

  depth++;
  switch (msg->type) {
  case PARSEBGP_BMP_TYPE_ROUTE_MON:
    parsebgp_bgp_dump_msg(msg->types.route_mon, depth);
    break;

  case PARSEBGP_BMP_TYPE_STATS_REPORT:
    dump_stats_report(msg->types.stats_report, depth);
    break;

  case PARSEBGP_BMP_TYPE_PEER_DOWN:
    dump_peer_down(msg->types.peer_down, depth);
    break;

  case PARSEBGP_BMP_TYPE_PEER_UP:
    dump_peer_up(msg->types.peer_up, depth);
    break;

  case PARSEBGP_BMP_TYPE_INIT_MSG:
    dump_init_msg(msg->types.init_msg, depth);
    break;

  case PARSEBGP_BMP_TYPE_TERM_MSG:
    dump_term_msg(msg->types.term_msg, depth);
    break;

  case PARSEBGP_BMP_TYPE_ROUTE_MIRROR_MSG:
    dump_route_mirror_msg(msg->types.route_mirror, depth);
    break;
  }
}
