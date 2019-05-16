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

#include "parsebgp_bgp_common_impl.h"
#include "parsebgp_bgp_update_impl.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include "parsebgp_bgp_update_ext_communities_impl.h"
#include "parsebgp_bgp_update_mp_reach_impl.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static parsebgp_error_t parse_nlris(parsebgp_bgp_update_nlris_t *nlris,
                                    const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_bgp_prefix_t *tuple;
  parsebgp_error_t err;

  nlris->prefixes_cnt = 0;

  if (nlris->len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  PARSEBGP_ASSERT(nlris->len <= remain);

  // read until we run out of message
  while (nread < nlris->len) {
    PARSEBGP_MAYBE_REALLOC(nlris->prefixes,
                           nlris->_prefixes_alloc_cnt, nlris->prefixes_cnt + 1);
    tuple = &nlris->prefixes[nlris->prefixes_cnt];
    nlris->prefixes_cnt++;

    // Fix the prefix type to v4 unicast
    tuple->type = PARSEBGP_BGP_PREFIX_UNICAST_IPV4;
    tuple->afi = PARSEBGP_BGP_AFI_IPV4;
    tuple->safi = PARSEBGP_BGP_SAFI_UNICAST;
    size_t max_pfx = 32;

    // Read the prefix length
    PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, tuple->len);

    // Prefix
    slen = nlris->len - nread;
    err = parsebgp_decode_prefix(tuple->len, tuple->addr, buf, &slen, max_pfx);
    if (err != PARSEBGP_OK) {
      if (err == PARSEBGP_PARTIAL_MSG) {
        // decode_prefix() reached the end of the nlris, not the buffer
        PARSEBGP_RETURN_INVALID_MSG_ERR;
      }
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_nlris(parsebgp_bgp_update_nlris_t *nlris)
{
  free(nlris->prefixes);
  nlris->prefixes_cnt = 0;
  nlris->_prefixes_alloc_cnt = 0;
}

static void clear_nlris(parsebgp_bgp_update_nlris_t *nlris)
{
  nlris->prefixes_cnt = 0;
}

static void dump_nlris(const parsebgp_bgp_update_nlris_t *nlris, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_nlris_t, depth);

  PARSEBGP_DUMP_INT(depth, "Prefixes Count", nlris->prefixes_cnt);

  parsebgp_bgp_prefixes_dump(nlris->prefixes, nlris->prefixes_cnt, depth + 1);
}

static parsebgp_error_t
parse_path_attr_as_path(int asn_4_byte, parsebgp_bgp_update_as_path_t *msg,
                        const uint8_t *buf, size_t *lenp, size_t remain, int raw)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bgp_update_as_path_seg_t *seg;
  int i;
  uint8_t asn_size;

  if (asn_4_byte) {
    asn_size = sizeof(uint32_t);
  } else {
    asn_size = sizeof(uint16_t);
  }

  msg->asn_4_byte = asn_4_byte;
  msg->segs_cnt = 0;
  msg->asns_cnt = 0;

  if (raw) {
    PARSEBGP_MAYBE_REALLOC(msg->raw, msg->_raw_alloc_len,
                           remain);
    memcpy(msg->raw, buf, remain);
    *lenp = remain;
    return PARSEBGP_OK;
  }

  while ((remain - nread) > 0) {
    // create a new segment
    PARSEBGP_MAYBE_REALLOC(msg->segs, msg->_segs_alloc_cnt, msg->segs_cnt + 1);
    seg = &(msg->segs)[msg->segs_cnt];
    msg->segs_cnt++;

    if ((len - nread) < 2) {
      return PARSEBGP_PARTIAL_MSG;
    }

    // Segment Type
    seg->type = *(buf++);

    // Segment Length (# ASNs)
    seg->asns_cnt = *(buf++);

    nread += 2;

    // do one length check to avoid doing checked memcpys
    if ((len - nread) < (asn_size * seg->asns_cnt)) {
      return PARSEBGP_PARTIAL_MSG;
    }

    if (seg->type == PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SEQ) {
      msg->asns_cnt += seg->asns_cnt;
    } else if (seg->type == PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SET) {
      // as per RFC 4271
      msg->asns_cnt++;
    } // else: don't count confederations as per RFC 5065

    // ensure there is enough space to store the ASNs (we store as 4-byte
    // regardless of what the path encoding is)
    PARSEBGP_MAYBE_REALLOC(seg->asns, seg->_asns_alloc_cnt, seg->asns_cnt);
    // Segment ASNs
    for (i = 0; i < seg->asns_cnt; i++) {
      if (asn_4_byte) {
        seg->asns[i] = nptohl(buf);
      } else {
        seg->asns[i] = nptohs(buf);
      }
      buf += asn_size;
    }
    nread += asn_size * seg->asns_cnt;
  }

  // TODO: remove:
  assert((remain - nread) == 0);
  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_path_attr_as_path_safe(int asn_4_byte, parsebgp_bgp_update_as_path_t *msg,
                             const uint8_t *buf, size_t *lenp, size_t remain, int raw)
{
  parsebgp_error_t err;
  // first we try just parsing as-is
  if ((err = parse_path_attr_as_path(asn_4_byte, msg, buf, lenp, remain,
                                     raw)) != PARSEBGP_OK &&
      asn_4_byte != 0) {
    // if we've been asked to do 4-byte parsing, then maybe the caller made a
    // mistake
    return parse_path_attr_as_path(0, msg, buf, lenp, remain, raw);
  }
  return err;
}

static void destroy_attr_as_path(parsebgp_bgp_update_as_path_t *msg)
{
  int i;
  if (msg == NULL) {
    return;
  }

  free(msg->raw);

  for (i = 0; i < msg->_segs_alloc_cnt; i++) {
    free(msg->segs[i].asns);
  }
  free(msg->segs);

  free(msg);
}

static void clear_attr_as_path(parsebgp_bgp_update_as_path_t *msg)
{
  int i;
  for (i = 0; i < msg->segs_cnt; i++) {
    msg->segs[i].asns_cnt = 0;
  }
  msg->segs_cnt = 0;
}

static void dump_attr_as_path(const parsebgp_bgp_update_as_path_t *msg,
    int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_as_path_t, depth);

  PARSEBGP_DUMP_INT(depth, "Segment Count", msg->segs_cnt);
  PARSEBGP_DUMP_INT(depth, "ASN Count*", msg->asns_cnt);

  depth++;
  int i;
  parsebgp_bgp_update_as_path_seg_t *seg;
  for (i = 0; i < msg->segs_cnt; i++) {
    seg = &msg->segs[i];

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_as_path_seg_t, depth);

    PARSEBGP_DUMP_INT(depth, "Type", seg->type);
    PARSEBGP_DUMP_INT(depth, "ASNs Count", seg->asns_cnt);
    PARSEBGP_DUMP_INFO(depth, "ASNs: ");
    int j;
    for (j = 0; j < seg->asns_cnt; j++) {
      if (j != 0) {
        fputs(" ", stdout);
      }
      printf("%" PRIu32, seg->asns[j]);
    }
    fputs("\n", stdout);
  }
}

static parsebgp_error_t
parse_path_attr_aggregator(int asn_4_byte,
                           parsebgp_bgp_update_aggregator_t *aggregator,
                           const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;

  // infer whether there is a 4-byte or 2-byte ASN in the aggregator attribute
  if (remain == 8) {
    asn_4_byte = 1;
  } else if (remain == 6) {
    asn_4_byte = 0;
  } else {
    PARSEBGP_RETURN_INVALID_MSG_ERR;
  }

  // Aggregator ASN
  if (asn_4_byte) {
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, aggregator->asn);
  } else {
    PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, aggregator->asn);
  }

  // Aggregator IP Address (IPv4-only)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, aggregator->addr);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_path_attr_communities(parsebgp_bgp_update_communities_t *msg,
                            const uint8_t *buf, size_t *lenp, size_t remain, int raw)
{
  size_t len = *lenp, nread = 0;
  int i;

  msg->communities_cnt = remain / sizeof(uint32_t);

  if (raw) {
    // don't actually parse the communities
    PARSEBGP_MAYBE_REALLOC(msg->raw, msg->_raw_alloc_len, remain);
    memcpy(msg->raw, buf, remain);
    *lenp = remain;
    return PARSEBGP_OK;
  }

  PARSEBGP_MAYBE_REALLOC(msg->communities,
                         msg->_communities_alloc_cnt, msg->communities_cnt);
  for (i = 0; i < msg->communities_cnt; i++) {
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->communities[i]);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_communities(parsebgp_bgp_update_communities_t *msg)
{
  if (msg == NULL) {
    return;
  }
  free(msg->communities);
  free(msg->raw);
  free(msg);
}

static void clear_attr_communities(parsebgp_bgp_update_communities_t *msg)
{
  msg->communities_cnt = 0;
}

static void dump_attr_communities(const parsebgp_bgp_update_communities_t *msg,
                                  int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_communities_t, depth);

  PARSEBGP_DUMP_INT(depth, "Communities Count", msg->communities_cnt);

  PARSEBGP_DUMP_INFO(depth, "Communities: ");
  int i;
  for (i = 0; i < msg->communities_cnt; i++) {
    if (i != 0) {
      fputs(" ", stdout);
    }
    printf("%" PRIu16 ":%" PRIu16, (uint16_t)(msg->communities[i] >> 16),
           (uint16_t)msg->communities[i]);
  }
  fputs("\n", stdout);
}

static parsebgp_error_t
parse_path_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg,
                             const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;

  msg->cluster_ids_cnt = remain / sizeof(uint32_t);

  PARSEBGP_MAYBE_REALLOC(msg->cluster_ids,
                         msg->_cluster_ids_alloc_cnt, msg->cluster_ids_cnt);

  for (i = 0; i < msg->cluster_ids_cnt; i++) {
    PARSEBGP_ASSERT((remain - nread) >= sizeof(uint32_t));
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->cluster_ids[i]);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg)
{
  if (msg == NULL) {
    return;
  }
  free(msg->cluster_ids);
  free(msg);
}

static void clear_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg)
{
  msg->cluster_ids_cnt = 0;
}

static void dump_attr_cluster_list(
    const parsebgp_bgp_update_cluster_list_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_cluster_list_t, depth);

  PARSEBGP_DUMP_INT(depth, "Cluster ID Count", msg->cluster_ids_cnt);

  PARSEBGP_DUMP_INFO(depth, "Cluster IDs: ");
  int i;
  for (i = 0; i < msg->cluster_ids_cnt; i++) {
    if (i != 0) {
      fputs(" ", stdout);
    }
    printf("%" PRIu32, msg->cluster_ids[i]);
  }
  fputs("\n", stdout);
}

static parsebgp_error_t
parse_path_attr_as_pathlimit(parsebgp_bgp_update_as_pathlimit_t *msg,
                             const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;

  // Max # ASNs
  PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, msg->max_asns);

  // ASN
  PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, msg->asn);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_path_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg,
                                  const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_bgp_update_large_community_t *comm;
#define LARGE_COMM_LEN 12

  PARSEBGP_ASSERT((remain % LARGE_COMM_LEN) == 0);

  msg->communities_cnt = remain / LARGE_COMM_LEN;

  PARSEBGP_MAYBE_REALLOC(msg->communities,
                         msg->_communities_alloc_cnt, msg->communities_cnt);

  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];

    // Global Admin
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, comm->global_admin);

    // Local Data Part 1
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, comm->local_1);

    // Local Data Part 2
    PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, comm->local_2);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void
destroy_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg)
{
  if (msg == NULL) {
    return;
  }
  free(msg->communities);
  free(msg);
}

static void
clear_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg)
{
  msg->communities_cnt = 0;
}

static void
dump_attr_large_communities(const parsebgp_bgp_update_large_communities_t *msg,
                            int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_large_communities_t, depth);

  PARSEBGP_DUMP_INT(depth, "Communities Count", msg->communities_cnt);

  PARSEBGP_DUMP_INFO(depth, "Communities: ");
  int i;
  parsebgp_bgp_update_large_community_t *comm;
  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];
    if (i != 0) {
      fputs(" ", stdout);
    }
    printf("%" PRIu32 ":%" PRIu32 ":%" PRIu32 " ", comm->global_admin,
           comm->local_1, comm->local_2);
  }
  fputs("\n", stdout);
}

parsebgp_error_t parsebgp_bgp_update_path_attrs_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_path_attrs_t *path_attrs,
  const uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_bgp_update_path_attr_t *attr;
  uint8_t flags_tmp, type_tmp;
  uint16_t len_tmp;
  parsebgp_error_t err = PARSEBGP_OK;

  path_attrs->attrs_cnt = 0;

  // Path Attributes Length
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, path_attrs->len);

  if (nread + path_attrs->len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  PARSEBGP_ASSERT(nread + path_attrs->len <= remain);
  remain = nread + path_attrs->len; // remaining within path attributes

  // read until we run out of attributes
  while (nread < remain) {

    /* Optimization: the vast majority of cases will short-circuit after the
     * <4 condition. */
    if ((remain - nread < 4) &&
      ((*buf & PARSEBGP_BGP_PATH_ATTR_FLAG_EXTENDED) || remain - nread < 3))
    {
      /* The remaining data in Path Attributes is insufficient to encode a
         single minimum-sized path attribute, and should be considered as
         "treat-as-withdraw" (https://tools.ietf.org/html/rfc7606#section-4).
       */
      PARSEBGP_SKIP_INVALID_MSG(opts, buf, nread, 0,
        "Path attribute requires at least 3-4 bytes, but only %d bytes remain.",
        (int)(remain - nread));
      // If we pass the above macro, the user wants us to struggle on.
      *lenp = remain;
      return PARSEBGP_OK;
    }

    /* Optimization: since the length was already checked above, we can skip
     * the PARSEBGP_DESERIALIZE_* calls and read the buf directly. */
    flags_tmp = *(buf++); // Attribute Flags
    type_tmp = *(buf++);  // Attribute Type
    if (flags_tmp & PARSEBGP_BGP_PATH_ATTR_FLAG_EXTENDED) {
      len_tmp = nptohs(buf); // Attribute Length
      buf += 2;
      nread += 4;
    } else {
      len_tmp = *buf; // Attribute Length
      buf += 1;
      nread += 3;
    }

    if (len_tmp > (remain - nread)) {
      /* The length of the path attribute would cause the Total Attribute
         Length to be exceeded, and should be considered as
         "treat-as-withdraw" (https://tools.ietf.org/html/rfc7606#section-4).
       */
      PARSEBGP_SKIP_INVALID_MSG(
        opts, buf, nread, 0,
        "Path attribute (type %d) has length %d, but only %d bytes remain.",
        type_tmp, len_tmp, (int)(remain - nread));
      // If we pass the above macro, the user wants us to struggle on.
      *lenp = remain;
      return PARSEBGP_OK;
    }

    // if this type is beyond the max type that we understand, skip it now
    if (type_tmp >= PARSEBGP_BGP_PATH_ATTRS_LEN) {
      PARSEBGP_SKIP_NOT_IMPLEMENTED(
        opts, buf, nread, len_tmp,
        "BGP UPDATE Path Attribute %d is not yet implemented", type_tmp);
      continue;
    }

    // has the user enabled the filter, and have they (implicitly) filtered out
    // this type of attribute
    if (opts->bgp.path_attr_filter_enabled &&
        opts->bgp.path_attr_filter[type_tmp] == 0) {
      // they don't want it. skip over the rest of the attribute
      nread += len_tmp;
      buf += len_tmp;
      continue;
    }

    attr = &path_attrs->attrs[type_tmp];
    if (attr->type != 0) {
      assert(attr->type == type_tmp);

      fprintf(stderr, "WARN: Duplicate Path Attribute (%d) found. Skipping\n",
              type_tmp);
      nread += len_tmp;
      buf += len_tmp;
      continue;
    }

    PARSEBGP_MAYBE_REALLOC(path_attrs->attrs_used,
                           path_attrs->_attrs_used_alloc_cnt,
                           path_attrs->attrs_cnt + 1);
    path_attrs->attrs_used[path_attrs->attrs_cnt] = type_tmp;
    path_attrs->attrs_cnt++;

    // Attribute Flags
    attr->flags = flags_tmp;

    // Attribute Type
    attr->type = type_tmp;

    // Attribute Length
    attr->len = len_tmp;

#define RAW(opts, attr) \
    (opts->bgp.path_attr_raw_enabled && opts->bgp.path_attr_raw[attr->type])

    slen = len - nread;
    switch (attr->type) {

    // NOTE: when adding new types, ensure slen is set to the number of bytes
    // read so that assert at the bottom is useful

    // Type 1:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
      PARSEBGP_ASSERT(attr->len == sizeof(attr->data.origin));
      PARSEBGP_DESERIALIZE_UINT8(buf, len, nread, attr->data.origin);
      slen = sizeof(attr->data.origin);
      break;

    // Type 2:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.as_path);
      if ((err = parse_path_attr_as_path_safe(opts->bgp.asn_4_byte,
                                              attr->data.as_path, buf, &slen,
                                              attr->len, RAW(opts, attr)))
                                              != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 3:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
      PARSEBGP_ASSERT(attr->len == sizeof(attr->data.next_hop));
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, attr->data.next_hop);
      slen = sizeof(attr->data.next_hop);
      break;

    // Type 4:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
      PARSEBGP_ASSERT(attr->len == sizeof(attr->data.med));
      PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, attr->data.med);
      slen = sizeof(attr->data.med);
      break;

    // Type 5:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
      PARSEBGP_ASSERT(attr->len == sizeof(attr->data.local_pref));
      PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, attr->data.local_pref);
      slen = sizeof(attr->data.local_pref);
      break;

    // Type 6:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
      // zero-length attr
      slen = 0;
      break;

    // Type 7
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AGGREGATOR:
      if ((err = parse_path_attr_aggregator(opts->bgp.asn_4_byte,
                                            &attr->data.aggregator, buf, &slen,
                                            attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 8
    case PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.communities);
      if ((err = parse_path_attr_communities(attr->data.communities, buf, &slen,
                                             attr->len, RAW(opts, attr)))
                                             != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 9
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
      PARSEBGP_ASSERT(attr->len == sizeof(attr->data.originator_id));
      PARSEBGP_DESERIALIZE_UINT32(buf, len, nread, attr->data.originator_id);
      slen = sizeof(attr->data.originator_id);
      break;

    // Type 10
    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.cluster_list);
      if ((err = parse_path_attr_cluster_list(
             attr->data.cluster_list, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    //...

    // Type 14
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.mp_reach);
      if ((err = parsebgp_bgp_update_mp_reach_decode(opts, attr->data.mp_reach,
                                                     buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 15
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.mp_unreach);
      if ((err = parsebgp_bgp_update_mp_unreach_decode(
             opts, attr->data.mp_unreach, buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 16
    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.ext_communities);
      if ((err = parsebgp_bgp_update_ext_communities_decode(
             opts, attr->data.ext_communities, buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 17
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH:
      // same as AS_PATH, but force 4-byte AS parsing
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.as_path);
      if ((err = parse_path_attr_as_path(1, attr->data.as_path, buf, &slen,
                                         attr->len, RAW(opts, attr)))
                                         != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 18
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_AGGREGATOR:
      // same as AGGREGATOR, but force 4-byte AS parsing
      if ((err = parse_path_attr_aggregator(1, &attr->data.aggregator, buf,
                                            &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // ...

    // Type 21
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATHLIMIT:
      if ((err = parse_path_attr_as_pathlimit(
             &attr->data.as_pathlimit, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    //...

    // Type 25
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.ext_communities);
      if ((err = parsebgp_bgp_update_ext_communities_ipv6_decode(
             opts, attr->data.ext_communities, buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // ...

    // Type 29
    case PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS:
      // TODO: add support for BGP-LS
      PARSEBGP_SKIP_NOT_IMPLEMENTED(
        opts, buf, nread, attr->len,
        "BGP UPDATE Path Attribute %d (BGP-LS) is not yet implemented",
        attr->type);
      slen = attr->len;
      break;

    // ...

    // Type 32
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      PARSEBGP_MAYBE_MALLOC_ZERO(attr->data.large_communities);
      if ((err = parse_path_attr_large_communities(attr->data.large_communities,
                                                   buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    default:
      PARSEBGP_SKIP_NOT_IMPLEMENTED(
        opts, buf, nread, attr->len,
        "BGP UPDATE Path Attribute %d is not yet implemented", attr->type);
      slen = attr->len;
      break;
    }
    PARSEBGP_ASSERT(slen == attr->len);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_path_attrs_destroy(
  parsebgp_bgp_update_path_attrs_t *msg)
{
  int i;
  parsebgp_bgp_update_path_attr_t *attr;

  if (msg == NULL) {
    return;
  }

  for (i = 0; i < PARSEBGP_BGP_PATH_ATTRS_LEN; i++) {
    attr = &msg->attrs[i];

    switch (i) {
    // Types with no dynamic memory:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AGGREGATOR:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_AGGREGATOR:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATHLIMIT:
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH:
      destroy_attr_as_path(attr->data.as_path);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES:
      destroy_attr_communities(attr->data.communities);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      destroy_attr_cluster_list(attr->data.cluster_list);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      parsebgp_bgp_update_mp_reach_destroy(attr->data.mp_reach);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      parsebgp_bgp_update_mp_unreach_destroy(attr->data.mp_unreach);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      parsebgp_bgp_update_ext_communities_destroy(attr->data.ext_communities);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS:
      // TODO: add support for BGP-LS
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      destroy_attr_large_communities(attr->data.large_communities);
      break;
    }
  }

  free(msg->attrs_used);
}

void parsebgp_bgp_update_path_attrs_clear(parsebgp_bgp_update_path_attrs_t *msg)
{
  int i;
  parsebgp_bgp_update_path_attr_t *attr;

  if (msg == NULL) {
    return;
  }

  for (i = 0; i < msg->attrs_cnt; i++) {
    attr = &msg->attrs[msg->attrs_used[i]];

    if (attr->type == 0) {
      continue;
    }

    switch (attr->type) {
    // Types with no dynamic memory:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AGGREGATOR:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_AGGREGATOR:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATHLIMIT:
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH:
      clear_attr_as_path(attr->data.as_path);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES:
      clear_attr_communities(attr->data.communities);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      clear_attr_cluster_list(attr->data.cluster_list);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      parsebgp_bgp_update_mp_reach_clear(attr->data.mp_reach);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      parsebgp_bgp_update_mp_unreach_clear(attr->data.mp_unreach);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      parsebgp_bgp_update_ext_communities_clear(attr->data.ext_communities);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS:
      // TODO: add support for BGP-LS
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      clear_attr_large_communities(attr->data.large_communities);
      break;
    }

    attr->type = 0;
  }

  msg->attrs_cnt = 0;
}

void parsebgp_bgp_update_path_attrs_dump(
    const parsebgp_bgp_update_path_attrs_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_path_attrs_t, depth);

  PARSEBGP_DUMP_INT(depth, "Length", msg->len);
  PARSEBGP_DUMP_INT(depth, "Attributes Count", msg->attrs_cnt);

  depth++;
  int i;
  const parsebgp_bgp_update_path_attr_t *attr;
  for (i = 0; i < PARSEBGP_BGP_PATH_ATTRS_LEN; i++) {
    attr = &msg->attrs[i];

    if (attr->type == 0) {
      continue;
    }

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_path_attr_t, depth);

    PARSEBGP_DUMP_INT(depth, "Flags", attr->flags);
    PARSEBGP_DUMP_INT(depth, "Type", attr->type);
    PARSEBGP_DUMP_INT(depth, "Length", attr->len);

    depth++;
    switch (attr->type) {

    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
      PARSEBGP_DUMP_INT(depth, "ORIGIN", attr->data.origin);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH:
      dump_attr_as_path(attr->data.as_path, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
      PARSEBGP_DUMP_IP(depth, "Next Hop", PARSEBGP_BGP_AFI_IPV4,
                       attr->data.next_hop);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
      PARSEBGP_DUMP_INT(depth, "MED", attr->data.med);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
      PARSEBGP_DUMP_INT(depth, "LOCAL_PREF", attr->data.local_pref);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
      PARSEBGP_DUMP_INFO(depth, "ATOMIC_AGGREGATE\n");
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_AGGREGATOR:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_AGGREGATOR:
      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_aggregator_t, depth);
      PARSEBGP_DUMP_INT(depth, "ASN", attr->data.aggregator.asn);
      PARSEBGP_DUMP_IP(depth, "IP", PARSEBGP_BGP_AFI_IPV4,
                       attr->data.aggregator.addr);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES:
      dump_attr_communities(attr->data.communities, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
      PARSEBGP_DUMP_INT(depth, "ORIGINATOR_ID", attr->data.originator_id);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      dump_attr_cluster_list(attr->data.cluster_list, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      parsebgp_bgp_update_mp_reach_dump(attr->data.mp_reach, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      parsebgp_bgp_update_mp_unreach_dump(attr->data.mp_unreach, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      parsebgp_bgp_update_ext_communities_dump(attr->data.ext_communities,
                                               depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATHLIMIT:
      PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_as_pathlimit_t, depth);
      PARSEBGP_DUMP_INT(depth, "Max # ASNs", attr->data.as_pathlimit.max_asns);
      PARSEBGP_DUMP_INT(depth, "ASN", attr->data.as_pathlimit.asn);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS:
      PARSEBGP_DUMP_INFO(depth, "BGP-LS Support Not Implemented\n");
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      dump_attr_large_communities(attr->data.large_communities, depth);
      break;

    default:
      PARSEBGP_DUMP_INFO(depth, "Unsupported Attribute\n");
      break;
    }
    depth--;
  }
}

parsebgp_error_t parsebgp_bgp_update_decode(parsebgp_opts_t *opts,
                                            parsebgp_bgp_update_t *msg,
                                            const uint8_t *buf, size_t *lenp,
                                            size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_error_t err;

  // Withdrawn Routes Length
  PARSEBGP_DESERIALIZE_UINT16(buf, len, nread, msg->withdrawn_nlris.len);

  // Withdrawn Routes
  slen = len - nread;
  if ((err = parse_nlris(&msg->withdrawn_nlris, buf, &slen, remain - nread)) !=
      PARSEBGP_OK) {
    return err;
  }
  assert(slen == msg->withdrawn_nlris.len);
  nread += slen;
  buf += slen;

  // Path Attributes
  slen = len - nread;
  if ((err = parsebgp_bgp_update_path_attrs_decode(
         opts, &msg->path_attrs, buf, &slen, remain - nread)) != PARSEBGP_OK) {
    return err;
  }
  assert(slen == sizeof(msg->path_attrs.len) + msg->path_attrs.len);
  nread += slen;
  buf += slen;

  // NLRIs
  slen = len - nread;
  msg->announced_nlris.len = remain - nread;
  if ((err = parse_nlris(&msg->announced_nlris, buf, &slen,
                         msg->announced_nlris.len)) != PARSEBGP_OK) {
    return err;
  }
  assert(slen == msg->announced_nlris.len);
  nread += slen;
  buf += slen;

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_destroy(parsebgp_bgp_update_t *msg)
{
  if (msg == NULL) {
    return;
  }

  destroy_nlris(&msg->withdrawn_nlris);
  destroy_nlris(&msg->announced_nlris);
  parsebgp_bgp_update_path_attrs_destroy(&msg->path_attrs);

  free(msg);
}

void parsebgp_bgp_update_clear(parsebgp_bgp_update_t *msg)
{
  if (msg == NULL) {
    return;
  }

  clear_nlris(&msg->withdrawn_nlris);
  clear_nlris(&msg->announced_nlris);
  parsebgp_bgp_update_path_attrs_clear(&msg->path_attrs);
}

void parsebgp_bgp_update_dump(const parsebgp_bgp_update_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_t, depth);

  PARSEBGP_DUMP_INFO(depth, "Withdrawn NLRIs:\n");
  dump_nlris(&msg->withdrawn_nlris, depth + 1);

  PARSEBGP_DUMP_INFO(depth, "Path Attributes:\n");
  parsebgp_bgp_update_path_attrs_dump(&msg->path_attrs, depth + 1);

  PARSEBGP_DUMP_INFO(depth, "Announced NLRIs:\n");
  dump_nlris(&msg->announced_nlris, depth + 1);
}
