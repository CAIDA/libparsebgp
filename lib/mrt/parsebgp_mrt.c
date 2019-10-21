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

#include "parsebgp_mrt.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include "parsebgp_bgp_update_impl.h"
#include "parsebgp_bgp_notification_impl.h"
#include "parsebgp_bgp_open_impl.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/** Number of bytes in the MRT common header (excluding extended timestamp
    field) */
#define MRT_HDR_LEN 12

/** Helper to deserialize an IP address into a 16-byte buffer ('to') based on
    provided AFI */
#define DESERIALIZE_IP(afi, buf, len, nread, to)                               \
  do {                                                                         \
    switch ((afi)) {                                                           \
    case PARSEBGP_BGP_AFI_IPV4:                                                \
      PARSEBGP_DESERIALIZE_BYTES(buf, len, nread, &(to), 4);                   \
      break;                                                                   \
                                                                               \
    case PARSEBGP_BGP_AFI_IPV6:                                                \
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, to);                           \
      break;                                                                   \
                                                                               \
    default:                                                                   \
      PARSEBGP_RETURN_INVALID_MSG_ERR;                                         \
    }                                                                          \
  } while (0)

static parsebgp_error_t parse_table_dump(parsebgp_opts_t *opts,
                                         parsebgp_bgp_afi_t afi,
                                         parsebgp_mrt_table_dump_t *msg,
                                         const uint8_t *buf, size_t *lenp,
                                         size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // View Number
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->view_number);

  // Sequence
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->sequence);

  // Prefix Address
  DESERIALIZE_IP(afi, buf, len, nread, msg->prefix);

  // Prefix Length
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->prefix_len);

  // Status (unused)
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->status);

  // Originated Time
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->originated_time);

  // Peer IP address
  DESERIALIZE_IP(afi, buf, len, nread, msg->peer_ip);

  // Peer ASN (2-byte only)
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);

  // Path Attributes
  slen = len - nread;
  if ((err = parsebgp_bgp_update_path_attrs_decode(
         opts, &msg->path_attrs, buf, &slen, remain - nread)) != PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_table_dump(parsebgp_bgp_afi_t afi,
                               parsebgp_mrt_table_dump_t *msg)
{
  if (msg == NULL) {
    return;
  }

  parsebgp_bgp_update_path_attrs_destroy(&msg->path_attrs);

  free(msg);
}

static void clear_table_dump(parsebgp_bgp_afi_t afi,
                             parsebgp_mrt_table_dump_t *msg)
{
  if (msg == NULL) {
    return;
  }

  parsebgp_bgp_update_path_attrs_clear(&msg->path_attrs);
}

static void dump_table_dump(parsebgp_bgp_afi_t afi,
                            const parsebgp_mrt_table_dump_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_t, depth);
  PARSEBGP_DUMP_INT(depth, "View Number", msg->view_number);
  PARSEBGP_DUMP_INT(depth, "Sequence", msg->sequence);
  PARSEBGP_DUMP_PFX(depth, "Prefix", afi, msg->prefix, msg->prefix_len);
  PARSEBGP_DUMP_INT(depth, "Status (unused)", msg->status);
  PARSEBGP_DUMP_INT(depth, "Originated Time", msg->originated_time);
  PARSEBGP_DUMP_IP(depth, "Peer IP", afi, msg->peer_ip);
  PARSEBGP_DUMP_INT(depth, "Peer ASN", msg->peer_asn);

  parsebgp_bgp_update_path_attrs_dump(&msg->path_attrs, depth + 1);
}

static parsebgp_error_t
parse_table_dump_v2_peer_index(parsebgp_mrt_table_dump_v2_peer_index_t *msg,
                               const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_mrt_table_dump_v2_peer_entry_t *pe = NULL;
  uint8_t u8;

  // Collector BGP ID
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->collector_bgp_id);

  // View Name Length
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->view_name_len);
  if (msg->view_name_len > (len - nread)) {
    return PARSEBGP_PARTIAL_MSG;
  }

  // View Name
  if (msg->view_name_len > 0) {
    PARSEBGP_MAYBE_REALLOC(msg->view_name,
                           msg->_view_name_alloc_len, msg->view_name_len + 1);
    memcpy(msg->view_name, buf, msg->view_name_len);
    msg->view_name[msg->view_name_len] = '\0';
    nread += msg->view_name_len;
    buf += msg->view_name_len;
  }

  // Peer Count
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_count);

  // allocate some space for the peer entries
  PARSEBGP_MAYBE_REALLOC(msg->peer_entries,
                         msg->_peer_entries_alloc_cnt, msg->peer_count);
  memset(msg->peer_entries, 0,
         sizeof(parsebgp_mrt_table_dump_v2_peer_entry_t) * msg->peer_count);

  // Peer Entries
  for (i = 0; i < msg->peer_count; i++) {
    pe = &msg->peer_entries[i];

    // Peer Type (discarded)
    PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, u8);

    // parse the peer type and afi
    pe->asn_type = (u8 & 0x02) >> 1;
    pe->ip_afi = (u8 & 0x01) + 1;

    // Peer BGP ID
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, pe->bgp_id);

    // Peer IP Address
    DESERIALIZE_IP(pe->ip_afi, buf, len, nread, pe->ip);

    // Peer ASN
    switch (pe->asn_type) {
    case PARSEBGP_MRT_ASN_2_BYTE:
      PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, pe->asn);
      break;

    case PARSEBGP_MRT_ASN_4_BYTE:
      PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, pe->asn);
      break;

    default:
      PARSEBGP_RETURN_INVALID_MSG_ERR;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void
destroy_table_dump_v2_peer_index(parsebgp_mrt_table_dump_v2_peer_index_t *msg)
{
  free(msg->view_name);
  msg->view_name = NULL;
  msg->view_name_len = 0;

  free(msg->peer_entries);
  msg->peer_entries = NULL;
  msg->peer_count = 0;
}

static void
clear_table_dump_v2_peer_index(parsebgp_mrt_table_dump_v2_peer_index_t *msg)
{
  if (msg == NULL) {
    return;
  }

  msg->view_name_len = 0;
  msg->peer_count = 0;
}

static void
dump_table_dump_v2_peer_index(
    const parsebgp_mrt_table_dump_v2_peer_index_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_peer_index_t, depth);

  PARSEBGP_DUMP_IP(depth, "Collector BGP ID", PARSEBGP_BGP_AFI_IPV4,
                   &msg->collector_bgp_id);
  PARSEBGP_DUMP_INFO(depth, "View Name: %s\n", msg->view_name);
  PARSEBGP_DUMP_INT(depth, "Peer Count", msg->peer_count);

  depth++;
  int i;
  parsebgp_mrt_table_dump_v2_peer_entry_t *entry;
  for (i = 0; i < msg->peer_count; i++) {
    entry = &msg->peer_entries[i];
    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_peer_entry_t, depth);
    PARSEBGP_DUMP_INT(depth, "ASN Type", entry->asn_type);
    PARSEBGP_DUMP_INT(depth, "IP AFI", entry->ip_afi);
    PARSEBGP_DUMP_IP(depth, "BGP ID", PARSEBGP_BGP_AFI_IPV4, &entry->bgp_id);
    PARSEBGP_DUMP_IP(depth, "IP", entry->ip_afi, entry->ip);
    PARSEBGP_DUMP_INT(depth, "ASN", entry->asn);
  }
}

static parsebgp_error_t parse_table_dump_v2_rib_entries(
  parsebgp_opts_t *opts, parsebgp_mrt_table_dump_v2_subtype_t subtype,
  parsebgp_mrt_table_dump_v2_rib_entry_t *entries, uint16_t entry_count,
  const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;
  parsebgp_error_t err;

  opts->bgp.asn_4_byte = 1;
  opts->bgp.mp_reach_no_afi_safi_reserved = 1;
  switch (subtype) {
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV4;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_UNICAST;
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV4;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_MULTICAST;
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV6;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_UNICAST;
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV6;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_MULTICAST;
    break;

  default:
    // programming error
    assert(0);
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  for (i = 0; i < entry_count; i++) {
    entry = &entries[i];

    // Peer Index
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, entry->peer_index);

    // Originated Time
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, entry->originated_time);

    // Path Attributes
    slen = len - nread;
    if ((err = parsebgp_bgp_update_path_attrs_decode(
           opts, &entry->path_attrs, buf, &slen, remain - nread)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_table_dump_v2_rib_entries(
  parsebgp_mrt_table_dump_v2_rib_entry_t *entries, uint16_t entry_alloc_cnt)
{
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;

  if (entries == NULL) {
    return;
  }

  for (i = 0; i < entry_alloc_cnt; i++) {
    entry = &entries[i];

    parsebgp_bgp_update_path_attrs_destroy(&entry->path_attrs);
  }

  free(entries);
}

static void
clear_table_dump_v2_rib_entries(parsebgp_mrt_table_dump_v2_rib_entry_t *entries,
                                uint16_t entry_count)
{
  int i;
  for (i = 0; i < entry_count; i++) {
    parsebgp_bgp_update_path_attrs_clear(&entries[i].path_attrs);
  }
}

static parsebgp_error_t
parse_table_dump_v2_afi_safi_rib(parsebgp_opts_t *opts,
                                 parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                 parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg,
                                 const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  size_t max_pfx;
  parsebgp_error_t err;

  // Sequence Number
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->sequence);

  // Prefix Length
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->prefix_len);

  // Prefix
  slen = len - nread;
  max_pfx = (subtype == PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST ||
             subtype == PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST) ?
              32 : 128;
  err = parsebgp_decode_prefix(msg->prefix_len, msg->prefix, buf, &slen,
      max_pfx);
  if (err != PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  // Entry Count
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->entry_count);

  // RIB Entries
  // allocate some memory for the entries
  PARSEBGP_MAYBE_REALLOC(msg->entries,
                         msg->_entries_alloc_cnt, msg->entry_count);

  // and then parse the entries
  slen = len - nread;
  if ((err = parse_table_dump_v2_rib_entries(
         opts, subtype, msg->entries, msg->entry_count, buf, &slen,
         (remain - nread))) != PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_table_dump_v2_afi_safi_rib(
  parsebgp_mrt_table_dump_v2_subtype_t subtype,
  parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg)
{
  destroy_table_dump_v2_rib_entries(msg->entries, msg->_entries_alloc_cnt);
  msg->entries = NULL;
  msg->entry_count = 0;
  msg->_entries_alloc_cnt = 0;
}

static void
clear_table_dump_v2_afi_safi_rib(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                 parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg)
{
  if (msg == NULL) {
    return;
  }
  clear_table_dump_v2_rib_entries(msg->entries, msg->entry_count);
  msg->entry_count = 0;
}

static void
dump_table_dump_v2_afi_safi_rib(
    parsebgp_mrt_table_dump_v2_subtype_t subtype,
    const parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg,
    int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_afi_safi_rib_t, depth);

  int afi = (subtype == PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST ||
             subtype == PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST)
              ? PARSEBGP_BGP_AFI_IPV4
              : PARSEBGP_BGP_AFI_IPV6;

  PARSEBGP_DUMP_INT(depth, "Sequence", msg->sequence);
  PARSEBGP_DUMP_PFX(depth, "Prefix", afi, msg->prefix, msg->prefix_len);
  PARSEBGP_DUMP_INT(depth, "Entry Count", msg->entry_count);

  depth++;
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;
  for (i = 0; i < msg->entry_count; i++) {
    entry = &msg->entries[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_rib_entry_t, depth);

    PARSEBGP_DUMP_INT(depth, "Peer Index", entry->peer_index);
    PARSEBGP_DUMP_INT(depth, "Originated Time", entry->originated_time);

    parsebgp_bgp_update_path_attrs_dump(&entry->path_attrs, depth + 1);
  }
}

static parsebgp_error_t parse_table_dump_v2(
  parsebgp_opts_t *opts, parsebgp_mrt_table_dump_v2_subtype_t subtype,
  parsebgp_mrt_table_dump_v2_t *msg, const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t nread = 0;
  // table dump v2 has no common header, so just call the appropriate subtype
  // parser
  switch (subtype) {
  case PARSEBGP_MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE:
    return parse_table_dump_v2_peer_index(&msg->peer_index, buf, lenp, remain);
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
    return parse_table_dump_v2_afi_safi_rib(opts, subtype, &msg->afi_safi_rib,
                                            buf, lenp, remain);
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_GENERIC:
    // these probably aren't too hard to support, but bgpdump doesn't support
    // them, so it likely means we don't have any actual use for it.
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain,
                                  "Unsupported MRT TABLE_DUMP_V2 subtype (%d)",
                                  subtype);
    // only used if we try and skip the unknown data:
    *lenp = nread;
    return PARSEBGP_OK;
    break;

  default:
    PARSEBGP_RETURN_INVALID_MSG_ERR;
    break;
  }
}

static void destroy_table_dump_v2(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                  parsebgp_mrt_table_dump_v2_t *msg)
{
  if (msg == NULL) {
    return;
  }

  destroy_table_dump_v2_peer_index(&msg->peer_index);
  destroy_table_dump_v2_afi_safi_rib(subtype, &msg->afi_safi_rib);

  free(msg);
}

static void clear_table_dump_v2(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                parsebgp_mrt_table_dump_v2_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // table dump v2 has no common header, so just call the appropriate subtype
  // clear
  switch (subtype) {
  case PARSEBGP_MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE:
    clear_table_dump_v2_peer_index(&msg->peer_index);
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
    clear_table_dump_v2_afi_safi_rib(subtype, &msg->afi_safi_rib);
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_GENERIC:
  default:
    break;
  }
}

static void dump_table_dump_v2(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                               const parsebgp_mrt_table_dump_v2_t *msg,
                               int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_t, depth);

  switch (subtype) {
  case PARSEBGP_MRT_TABLE_DUMP_V2_PEER_INDEX_TABLE:
    dump_table_dump_v2_peer_index(&msg->peer_index, depth + 1);
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_UNICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_UNICAST:
  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
    dump_table_dump_v2_afi_safi_rib(subtype, &msg->afi_safi_rib, depth + 1);
    break;

  case PARSEBGP_MRT_TABLE_DUMP_V2_RIB_GENERIC:
  default:
    break;
  }
}

/**
   NOTE:
   `parse_bgp` function parses MRT Type 5 message (deprecated):
   https://tools.ietf.org/html/rfc6396#appendix-B.2.1
   This type of message format was only used in very old archive files.

   For newer archive data that uses MRT Type 16 or 17 (BGP4MP or BGP4MP_ET),
   `parse_bgp4mp` function should be used.
*/
static parsebgp_error_t parse_bgp(parsebgp_opts_t *opts,
                                  parsebgp_mrt_bgp_subtype_t subtype,
                                  parsebgp_mrt_bgp_t *msg, const uint8_t *buf,
                                  size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_error_t err;

  // 2-byte Peer ASN
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);

  // Peer IP
  DESERIALIZE_IP(PARSEBGP_BGP_AFI_IPV4, buf, len, nread, msg->peer_ip);

  switch (subtype) {
  case PARSEBGP_MRT_BGP_MESSAGE_NULL:
  // The BGP_NULL Subtype is a reserved Subtype.
  case PARSEBGP_MRT_BGP_MESSAGE_PREF_UPDATE:
  // The BGP_PREF_UPDATE Subtype is not defined.
  case PARSEBGP_MRT_BGP_MESSAGE_SYNC:
    // There are no known implementations of this subtype, and it SHOULD be
    // ignored.
    break;

  case PARSEBGP_MRT_BGP_MESSAGE_NOTIFY:
    // 2-byte Local ASN
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);
    // Local IP
    DESERIALIZE_IP(PARSEBGP_BGP_AFI_IPV4, buf, len, nread, msg->local_ip);

    PARSEBGP_MAYBE_MALLOC_ZERO(msg->data.notification);
    err = parsebgp_bgp_notification_decode(opts, msg->data.notification, buf,
                                           &slen, remain - nread);
    break;

  case PARSEBGP_MRT_BGP_MESSAGE_KEEPALIVE: // subtype 7
    // 2-byte Local ASN
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);
    // Local IP
    DESERIALIZE_IP(PARSEBGP_BGP_AFI_IPV4, buf, len, nread, msg->local_ip);

    err = PARSEBGP_OK;
    slen = 0;
    break;

  case PARSEBGP_MRT_BGP_MESSAGE_OPEN: // subtype 5
    // 2-byte Local ASN
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);
    // Local IP
    DESERIALIZE_IP(PARSEBGP_BGP_AFI_IPV4, buf, len, nread, msg->local_ip);

    PARSEBGP_MAYBE_MALLOC_ZERO(msg->data.open);
    slen = len - nread;
    if ((err = parsebgp_bgp_open_decode(opts, msg->data.open, buf, &slen,
                                        remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_MRT_BGP_MESSAGE_STATE_CHANGE: // subtype 3
    // Old State
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->data.state_change.old_state);
    // New State
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->data.state_change.new_state);
    break;

  case PARSEBGP_MRT_BGP_MESSAGE_UPDATE: // subtype 1
    // 2-byte Local ASN
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);
    // Local IP
    DESERIALIZE_IP(PARSEBGP_BGP_AFI_IPV4, buf, len, nread, msg->local_ip);

    PARSEBGP_MAYBE_MALLOC_ZERO(msg->data.update);
    slen = len - nread;
    if ((err = parsebgp_bgp_update_decode(opts, msg->data.update, buf, &slen,
                                          remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    PARSEBGP_RETURN_INVALID_MSG_ERR;
    break;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t parse_bgp4mp(parsebgp_opts_t *opts,
                                     parsebgp_mrt_bgp4mp_subtype_t subtype,
                                     parsebgp_mrt_bgp4mp_t *msg, const uint8_t *buf,
                                     size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_error_t err = PARSEBGP_OK;

  // ASN fields
  switch (subtype) {
  // 2-byte ASN subtypes:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
    // Peer ASN
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->peer_asn);

    // Local ASN
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->local_asn);
    break;

  // 4-byte ASN subtypes:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    // Peer ASN
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->peer_asn);

    // Local ASN
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->local_asn);
    break;

  default:
    PARSEBGP_SKIP_INVALID_MSG(opts, buf, nread, remain,
      "unknown bgp4mp subtype %d", subtype);
    *lenp = nread;
    return PARSEBGP_OK; // skip
  }

  // The following checks are to handle non-compliant MRT data from
  // really old Quagga versions which did not dump ifindex or src/dest
  // IPs in STATE_CHANGE and OPEN messages.
  // For the state change, we can easily detect this by checking the
  // subtype and length, but for OPEN, we have to peek and see if the
  // AFI appears to be 0xFFFF which is actually the part of the BGP
  // marker.
  if ((subtype == PARSEBGP_MRT_BGP4MP_STATE_CHANGE && len == 8) ||
      (subtype == PARSEBGP_MRT_BGP4MP_MESSAGE && (len - nread) > 4 &&
       remain > 4 && memcmp(buf+2, "\xff\xff", 2) == 0)) {
    msg->interface_index = 0;
    msg->afi = 0;
    memset(msg->peer_ip, 0, sizeof(msg->peer_ip));
    memset(msg->local_ip, 0, sizeof(msg->local_ip));
  } else { // normal case
    // Interface Index
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->interface_index);

    // Address Family
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->afi);

    // Peer IP
    DESERIALIZE_IP(msg->afi, buf, len, nread, msg->peer_ip);

    // Local IP
    DESERIALIZE_IP(msg->afi, buf, len, nread, msg->local_ip);
  }

  // And then the actual data, based on the subtype
  // the _AS4 subtypes actually only change the common part of the message, so
  // we can treat them the same as their non-AS4 subtype at this point.
  switch (subtype) {
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
    // Old State
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->data.state_change.old_state);

    // New State
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->data.state_change.new_state);
    break;

  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    opts->bgp.asn_4_byte = 1;
  // FALL THROUGH

  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
  case PARSEBGP_MRT_BGP4MP_MESSAGE:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->data.bgp_msg);
    slen = len - nread;
    err = parsebgp_bgp_decode_ext(opts, msg->data.bgp_msg, buf, &slen, 1);
    if (err != PARSEBGP_OK && err != PARSEBGP_TRUNCATED_MSG) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    PARSEBGP_RETURN_INVALID_MSG_ERR;
    break;
  }

  *lenp = nread;
  return err;
}

static void destroy_bgp4mp(parsebgp_mrt_bgp4mp_subtype_t subtype,
                           parsebgp_mrt_bgp4mp_t *msg)
{
  if (msg == NULL) {
    return;
  }

  parsebgp_bgp_destroy_msg(msg->data.bgp_msg);

  free(msg);
}

static void clear_bgp4mp(parsebgp_mrt_bgp4mp_subtype_t subtype,
                         parsebgp_mrt_bgp4mp_t *msg)
{
  if (msg == NULL) {
    return;
  }

  switch (subtype) {
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
    // no dynamic memory used
    break;

  case PARSEBGP_MRT_BGP4MP_MESSAGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    parsebgp_bgp_clear_msg(msg->data.bgp_msg);
    break;

  default:
    break;
  }
}

static void dump_bgp4mp(parsebgp_mrt_bgp4mp_subtype_t subtype,
                        const parsebgp_mrt_bgp4mp_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_bgp4mp_t, depth);

  PARSEBGP_DUMP_INT(depth, "Peer ASN", msg->peer_asn);
  PARSEBGP_DUMP_INT(depth, "Local ASN", msg->local_asn);
  PARSEBGP_DUMP_INT(depth, "Interface Index", msg->interface_index);
  PARSEBGP_DUMP_INT(depth, "AFI", msg->afi);
  PARSEBGP_DUMP_IP(depth, "Peer IP", msg->afi, msg->peer_ip);
  PARSEBGP_DUMP_IP(depth, "Local IP", msg->afi, msg->local_ip);

  depth++;
  switch (subtype) {
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_bgp4mp_state_change_t, depth);

    PARSEBGP_DUMP_INT(depth, "Old State", msg->data.state_change.old_state);
    PARSEBGP_DUMP_INT(depth, "New State", msg->data.state_change.new_state);
    break;

  case PARSEBGP_MRT_BGP4MP_MESSAGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    parsebgp_bgp_dump_msg(msg->data.bgp_msg, depth);
    break;

  default:
    break;
  }
}

static parsebgp_error_t parse_common_hdr(parsebgp_opts_t *opts,
                                         parsebgp_mrt_msg_t *msg, const uint8_t *buf,
                                         size_t *lenp)
{
  size_t len = *lenp, nread = 0;

  // Timestamp
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->timestamp_sec);

  // Type
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->type);

  // Sub-type
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->subtype);

  // Length
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->len);
  if (msg->len > len - nread) {
    return PARSEBGP_PARTIAL_MSG;
  }

  // maybe parse the microsecond timestamp (also validates supported message
  // types)
  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->timestamp_usec);
    break;

  case PARSEBGP_MRT_TYPE_BGP:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
    // no usec timestamp to read
    break;

  default:
    // unknown message type
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void dump_common_hdr(const parsebgp_mrt_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_INT(depth, "Timestamp.sec", msg->timestamp_sec);
  PARSEBGP_DUMP_INT(depth, "Type", msg->type);
  PARSEBGP_DUMP_INT(depth, "Subtype", msg->subtype);
  PARSEBGP_DUMP_INT(depth, "Length", msg->len);
  PARSEBGP_DUMP_INT(depth, "Timestamp.usec", msg->timestamp_usec);
}

parsebgp_error_t parsebgp_mrt_decode(parsebgp_opts_t *opts,
                                     parsebgp_mrt_msg_t *msg, const uint8_t *buf,
                                     size_t *len)
{
  parsebgp_error_t err = PARSEBGP_OK;
  size_t slen = 0, nread = 0, remain = 0;

  // First, parse the common header
  slen = *len;
  if ((err = parse_common_hdr(opts, msg, buf, &slen)) != PARSEBGP_OK) {
    return err;
  }
  nread += slen;

  slen = *len - nread; // number of bytes left in the buffer
  // set remain, the (alleged) number of bytes left in the message
  if (nread == MRT_HDR_LEN) {
    // normal header without extended timestamp
    remain = msg->len;
  } else if (nread == MRT_HDR_LEN + sizeof(msg->timestamp_usec)) {
    // timestamp_usec is *included* in the reported msg len, need to subtract
    // since we've already read it
    remain = msg->len - sizeof(msg->timestamp_usec);
  } else {
    // uh oh
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }
  if (remain > slen) {
    // the buffer is too short to hold the full MRT msg; give up now
    return PARSEBGP_PARTIAL_MSG;
  }

  slen = remain; // don't let sub-parsers go past the end of the MRT message
  switch (msg->type) {

  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.table_dump);
    err = parse_table_dump(opts, msg->subtype, msg->types.table_dump,
                           buf + nread, &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.table_dump_v2);
    err = parse_table_dump_v2(opts, msg->subtype, msg->types.table_dump_v2,
                              buf + nread, &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.bgp4mp);
    err = parse_bgp4mp(opts, msg->subtype, msg->types.bgp4mp, buf + nread,
                       &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_BGP:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.bgp);
    err =
      parse_bgp(opts, msg->subtype, msg->types.bgp, buf + nread, &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    slen = 0;
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, slen, msg->len,
                                  "MRT Type %d not supported", msg->type);
    break;

  default:
    // unknown message type
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }
  if (err != PARSEBGP_OK && err != PARSEBGP_TRUNCATED_MSG) {
    return err;
  }
  nread += slen;

  if ((MRT_HDR_LEN + msg->len) != nread) {
    // reported message length is incorrect
    //
    // previously we were trying to do our best to struggle on past this corrupt
    // data, but this was problematic and lead to more problems. now we just
    // decide that this file is corrupt and stop processing. (i have not seen
    // any examples of data where trying to carry on actually resulted in
    // parsing any more data, so this is hardly a sacrifice.)
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  *len = nread;
  return err;
}

void parsebgp_mrt_destroy_msg(parsebgp_mrt_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // common header has no dynamically allocated memory

  // free per-type memory
  destroy_table_dump(msg->subtype, msg->types.table_dump);
  destroy_table_dump_v2(msg->subtype, msg->types.table_dump_v2);
  destroy_bgp4mp(msg->subtype, msg->types.bgp4mp);

  free(msg);

  return;
}

void parsebgp_mrt_clear_msg(parsebgp_mrt_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    clear_table_dump(msg->subtype, msg->types.table_dump);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    clear_table_dump_v2(msg->subtype, msg->types.table_dump_v2);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    clear_bgp4mp(msg->subtype, msg->types.bgp4mp);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    break;
  }
}

void parsebgp_mrt_dump_msg(const parsebgp_mrt_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_msg_t, depth);
  dump_common_hdr(msg, depth);

  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    dump_table_dump(msg->subtype, msg->types.table_dump, depth + 1);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    dump_table_dump_v2(msg->subtype, msg->types.table_dump_v2, depth + 1);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    dump_bgp4mp(msg->subtype, msg->types.bgp4mp, depth + 1);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    break;
  }
}
