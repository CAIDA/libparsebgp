#include "parsebgp_bgp_update.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static parsebgp_error_t parse_nlris(parsebgp_bgp_update_nlris_t *nlris,
                                    uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_bgp_prefix_t *tuple;
  parsebgp_error_t err;

  nlris->prefixes = NULL;
  nlris->prefixes_cnt = 0;

  if (nlris->len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  if (nlris->len > remain) {
    return PARSEBGP_INVALID_MSG;
  }

  // read and realloc until we run out of message
  while (nread < nlris->len) {
    // optimistically allocate a new prefix tuple
    if ((nlris->prefixes =
           realloc(nlris->prefixes, sizeof(parsebgp_bgp_prefix_t) *
                                      ((nlris->prefixes_cnt) + 1))) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    tuple = &nlris->prefixes[nlris->prefixes_cnt];
    nlris->prefixes_cnt++;

    // Fix the prefix type to v4 unicast
    tuple->type = PARSEBGP_BGP_PREFIX_UNICAST_IPV4;
    tuple->afi = PARSEBGP_BGP_AFI_IPV4;
    tuple->safi = PARSEBGP_BGP_SAFI_UNICAST;

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

static void destroy_nlris(parsebgp_bgp_update_nlris_t *nlris)
{
  if (nlris == NULL) {
    return;
  }
  free(nlris->prefixes);
  nlris->prefixes_cnt = 0;
}

static void dump_nlris(parsebgp_bgp_update_nlris_t *nlris, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_nlris_t, depth);

  PARSEBGP_DUMP_INT(depth, "Prefixes Count", nlris->prefixes_cnt);

  parsebgp_bgp_dump_prefixes(nlris->prefixes, nlris->prefixes_cnt, depth + 1);
}

static parsebgp_error_t
parse_path_attr_as_path(int asn_4_byte, parsebgp_bgp_update_as_path_t *msg,
                        uint8_t *buf, size_t *lenp, size_t remain, int raw)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bgp_update_as_path_seg_t *seg;
  uint16_t u16;
  int i;

  msg->asn_4_byte = asn_4_byte;
  msg->segs = NULL;
  msg->segs_cnt = 0;

  if (raw) {
    if ((msg->raw = malloc(remain)) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    memcpy(msg->raw, buf, remain);
    *lenp = remain;
    return PARSEBGP_OK;
  }
  msg->raw = NULL;

  while ((remain - nread) > 0) {
    // create a new segment
    if ((msg->segs =
           realloc(msg->segs, sizeof(parsebgp_bgp_update_as_path_seg_t) *
                                ((msg->segs_cnt) + 1))) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    seg = &(msg->segs)[msg->segs_cnt];
    seg->asns = NULL; // in case we error out
    msg->segs_cnt++;

    // Segment Type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, seg->type);

    // Segment Length (# ASNs)
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, seg->asns_cnt);

    switch (seg->type) {
    case PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SET:
      // as per RFC 4271
      msg->asns_cnt++;
      break;

    case PARSEBGP_BGP_UPDATE_AS_PATH_SEG_AS_SEQ:
      msg->asns_cnt += seg->asns_cnt;
      break;

    default:
      // don't count confederations as per RFC 5065
      break;
    }

    // allocate enough space to store the ASNs (we store as 4-byte regardless of
    // what the path encoding is)
    if ((seg->asns = malloc(sizeof(uint32_t) * seg->asns_cnt)) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }

    // Segment ASNs
    for (i = 0; i < seg->asns_cnt; i++) {
      if (asn_4_byte) {
        PARSEBGP_DESERIALIZE_VAL(buf, len, nread, seg->asns[i]);
        seg->asns[i] = ntohl(seg->asns[i]);
      } else {
        PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u16);
        seg->asns[i] = ntohs(u16);
      }
    }
  }
  assert((remain - nread) == 0);

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_as_path(parsebgp_bgp_update_as_path_t *msg)
{
  int i;

  free(msg->raw);

  for (i = 0; i < msg->segs_cnt; i++) {
    free(msg->segs[i].asns);
  }
  free(msg->segs);
}

static void dump_attr_as_path(parsebgp_bgp_update_as_path_t *msg, int depth)
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
        printf(" ");
      }
      printf("%" PRIu32, seg->asns[j]);
    }
    printf("\n");
  }
}

static parsebgp_error_t
parse_path_attr_aggregator(int asn_4_byte,
                           parsebgp_bgp_update_aggregator_t *aggregator,
                           uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  uint16_t u16;

  // Aggregator ASN
  if (asn_4_byte) {
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, aggregator->asn);
    aggregator->asn = ntohl(aggregator->asn);
  } else {
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u16);
    aggregator->asn = ntohs(u16);
  }

  // Aggregator IP Address (IPv4-only)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, aggregator->addr);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_path_attr_communities(parsebgp_bgp_update_communities_t *msg,
                            uint8_t *buf, size_t *lenp, size_t remain,
                            int raw)
{
  size_t len = *lenp, nread = 0;
  int i;

  msg->communities_cnt = remain / sizeof(uint32_t);

  if (raw) {
    // don't actually parse the communities
    if ((msg->raw = malloc(remain)) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    memcpy(msg->raw, buf, remain);
    msg->communities = NULL;
    *lenp = remain;
    return PARSEBGP_OK;
  }
  msg->raw = NULL;

  if ((msg->communities = malloc(remain)) == NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  for (i = 0; i < msg->communities_cnt; i++) {
    if ((remain - nread) < sizeof(uint32_t)) {
      return PARSEBGP_INVALID_MSG;
    }
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->communities[i]);
    msg->communities[i] = ntohl(msg->communities[i]);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_communities(parsebgp_bgp_update_communities_t *msg)
{
  free(msg->communities);
  free(msg->raw);
}

static void dump_attr_communities(parsebgp_bgp_update_communities_t *msg,
                                  int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_communities_t, depth);

  PARSEBGP_DUMP_INT(depth, "Communities Count", msg->communities_cnt);

  PARSEBGP_DUMP_INFO(depth, "Communities: ");
  int i;
  for (i = 0; i < msg->communities_cnt; i++) {
    if (i != 0) {
      printf(" ");
    }
    printf("%" PRIu16 ":%" PRIu16, (uint16_t)(msg->communities[i] >> 16),
           (uint16_t)msg->communities[i]);
  }
  printf("\n");
}

static parsebgp_error_t
parse_path_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg,
                             uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;

  msg->cluster_ids_cnt = remain / sizeof(uint32_t);

  if ((msg->cluster_ids = malloc(sizeof(uint32_t) * msg->cluster_ids_cnt)) ==
      NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  for (i = 0; i < msg->cluster_ids_cnt; i++) {
    if ((remain - nread) < sizeof(uint32_t)) {
      return PARSEBGP_INVALID_MSG;
    }
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->cluster_ids[i]);
    msg->cluster_ids[i] = ntohl(msg->cluster_ids[i]);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg)
{
  free(msg->cluster_ids);
}

static void dump_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg,
                                   int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_cluster_list_t, depth);

  PARSEBGP_DUMP_INT(depth, "Cluster ID Count", msg->cluster_ids_cnt);

  PARSEBGP_DUMP_INFO(depth, "Cluster IDs: ");
  int i;
  for (i = 0; i < msg->cluster_ids_cnt; i++) {
    if (i != 0) {
      printf(" ");
    }
    printf("%" PRIu32, msg->cluster_ids[i]);
  }
  printf("\n");
}

static parsebgp_error_t
parse_path_attr_as_pathlimit(parsebgp_bgp_update_as_pathlimit_t *msg,
                             uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;

  // Max # ASNs
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->max_asns);

  // ASN
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->asn);
  msg->asn = ntohs(msg->asn);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_path_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg,
                                  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_bgp_update_large_community_t *comm;

  if ((remain % 12) != 0) {
    return PARSEBGP_INVALID_MSG;
  }

  msg->communities_cnt = remain / 12;

  if ((msg->communities = malloc(12 * msg->communities_cnt)) == NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];

    // Global Admin
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->global_admin);
    comm->global_admin = ntohl(comm->global_admin);

    // Local Data Part 1
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->local_1);
    comm->local_1 = ntohl(comm->local_1);

    // Local Data Part 2
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->local_2);
    comm->local_2 = ntohl(comm->local_2);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void
destroy_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg)
{
  free(msg->communities);
}

static void
dump_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg,
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
      printf(" ");
    }
    printf("%" PRIu32 ":%" PRIu32 ":%" PRIu32 " ", comm->global_admin,
           comm->local_1, comm->local_2);
  }
  printf("\n");
}

#define CHECK_REMAIN(remain, val)                                              \
  do {                                                                         \
    if (remain < sizeof(val)) {                                                \
      return PARSEBGP_INVALID_MSG;                                             \
    }                                                                          \
  } while (0)

#define PARSE_SIMPLE_ATTR(val, buf, len, nread, remain)                        \
  do {                                                                         \
    CHECK_REMAIN(remain, (val));                                               \
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, (val));                          \
    switch (sizeof(val)) {                                                     \
    case 1:                                                                    \
      break;                                                                   \
    case 2:                                                                    \
      val = ntohs(val);                                                        \
      break;                                                                   \
    case 4:                                                                    \
      val = ntohl(val);                                                        \
      break;                                                                   \
    case 8:                                                                    \
      val = ntohll(val);                                                       \
      break;                                                                   \
    default:                                                                   \
      /* unsupported value size */                                             \
      assert(0);                                                               \
      break;                                                                   \
    }                                                                          \
  } while (0)

parsebgp_error_t parsebgp_bgp_update_path_attrs_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_path_attrs_t *path_attrs,
  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_bgp_update_path_attr_t *attr;
  uint8_t flags_tmp, type_tmp;
  uint16_t len_tmp;
  uint8_t u8;
  parsebgp_error_t err = PARSEBGP_OK;
  int raw = 0;

  path_attrs->attrs_cnt = 0;

  // Path Attributes Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, path_attrs->len);
  path_attrs->len = ntohs(path_attrs->len);

  if (path_attrs->len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  if (path_attrs->len > remain) {
    return PARSEBGP_INVALID_MSG;
  }

  // read until we run out of attributes
  while (nread < path_attrs->len) {

    // Attribute Flags
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, flags_tmp);

    // Attribute Type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, type_tmp);

    // Attribute Length
    if (flags_tmp & PARSEBGP_BGP_PATH_ATTR_FLAG_EXTENDED) {
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, len_tmp);
      len_tmp = ntohs(len_tmp);
    } else {
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);
      len_tmp = u8;
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
    path_attrs->attrs_cnt++;

    if (opts->bgp.path_attr_raw_enabled &&
        opts->bgp.path_attr_raw[type_tmp] != 0) {
      raw = 1;
    } else {
      raw = 0;
    }

    // Attribute Flags
    attr->flags = flags_tmp;

    // Attribute Type
    attr->type = type_tmp;

    // Attribute Length
    attr->len = len_tmp;

    if (attr->len > (remain - nread)) {
      return PARSEBGP_INVALID_MSG;
    }
    if (attr->len > (len - nread)) {
      return PARSEBGP_PARTIAL_MSG;
    }

    slen = len - nread;
    switch (attr->type) {

    // Type 1:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
      PARSE_SIMPLE_ATTR(attr->data.origin, buf, len, nread, remain);
      break;

    // Type 2:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH:
      if ((err = parse_path_attr_as_path(opts->bgp.asn_4_byte,
                                         &attr->data.as_path, buf, &slen,
                                         attr->len, raw)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 3:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
      CHECK_REMAIN(remain, attr->data.next_hop);
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, attr->data.next_hop);
      break;

    // Type 4:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
      PARSE_SIMPLE_ATTR(attr->data.med, buf, len, nread, remain);
      break;

    // Type 5:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
      PARSE_SIMPLE_ATTR(attr->data.local_pref, buf, len, nread, remain);
      break;

    // Type 6:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
      // zero-length attr
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
      if ((err = parse_path_attr_communities(&attr->data.communities, buf,
                                             &slen, attr->len, raw)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 9
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
      PARSE_SIMPLE_ATTR(attr->data.originator_id, buf, len, nread, remain);
      break;

    // Type 10
    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      if ((err = parse_path_attr_cluster_list(
             &attr->data.cluster_list, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    //...

    // Type 14
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      if ((err = parsebgp_bgp_update_mp_reach_decode(opts, &attr->data.mp_reach,
                                                     buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 15
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      if ((err = parsebgp_bgp_update_mp_unreach_decode(
             opts, &attr->data.mp_unreach, buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 16
    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
      if ((err = parsebgp_bgp_update_ext_communities_decode(
             opts, &attr->data.ext_communities, buf, &slen, attr->len)) !=
          PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;

    // Type 17
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH:
      // same as AS_PATH, but force 4-byte AS parsing
      if ((err = parse_path_attr_as_path(1, &attr->data.as_path, buf, &slen,
                                         attr->len, raw)) != PARSEBGP_OK) {
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
      if ((err = parsebgp_bgp_update_ext_communities_ipv6_decode(
             opts, &attr->data.ext_communities, buf, &slen, attr->len)) !=
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
      break;

    // ...

    // Type 32
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      if ((err = parse_path_attr_large_communities(
             &attr->data.large_communities, buf, &slen, attr->len)) !=
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
      break;
    }
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

  for (i = 0; i < UINT8_MAX; i++) {
    attr = &msg->attrs[i];

    // sanity check
    assert(attr->type == 0 || attr->type == i);

    switch (attr->type) {
    case 0:
      // unpopulated attribute
      break;

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
      destroy_attr_as_path(&attr->data.as_path);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES:
      destroy_attr_communities(&attr->data.communities);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      destroy_attr_cluster_list(&attr->data.cluster_list);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      parsebgp_bgp_update_mp_reach_destroy(&attr->data.mp_reach);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      parsebgp_bgp_update_mp_unreach_destroy(&attr->data.mp_unreach);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      parsebgp_bgp_update_ext_communities_destroy(&attr->data.ext_communities);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS:
      // TODO: add support for BGP-LS
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      destroy_attr_large_communities(&attr->data.large_communities);
      break;
    }
  }

  msg->attrs_cnt = 0;
}

void parsebgp_bgp_update_path_attrs_dump(parsebgp_bgp_update_path_attrs_t *msg,
                                         int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_path_attrs_t, depth);

  PARSEBGP_DUMP_INT(depth, "Length", msg->len);
  PARSEBGP_DUMP_INT(depth, "Attributes Count", msg->attrs_cnt);

  depth++;
  int i;
  parsebgp_bgp_update_path_attr_t *attr;
  for (i = 0; i < UINT8_MAX; i++) {
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
      dump_attr_as_path(&attr->data.as_path, depth);
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
      dump_attr_communities(&attr->data.communities, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
      PARSEBGP_DUMP_INT(depth, "ORIGINATOR_ID", attr->data.originator_id);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      dump_attr_cluster_list(&attr->data.cluster_list, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      parsebgp_bgp_update_mp_reach_dump(&attr->data.mp_reach, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      parsebgp_bgp_update_mp_unreach_dump(&attr->data.mp_unreach, depth);
      break;

    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      parsebgp_bgp_update_ext_communities_dump(&attr->data.ext_communities,
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
      dump_attr_large_communities(&attr->data.large_communities, depth);
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
                                            uint8_t *buf, size_t *lenp,
                                            size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_error_t err;

  // Withdrawn Routes Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->withdrawn_nlris.len);
  msg->withdrawn_nlris.len = ntohs(msg->withdrawn_nlris.len);

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
}

void parsebgp_bgp_update_dump(parsebgp_bgp_update_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_t, depth);

  PARSEBGP_DUMP_INFO(depth, "Withdrawn NLRIs:\n");
  dump_nlris(&msg->withdrawn_nlris, depth + 1);

  PARSEBGP_DUMP_INFO(depth, "Path Attributes:\n");
  parsebgp_bgp_update_path_attrs_dump(&msg->path_attrs, depth + 1);

  PARSEBGP_DUMP_INFO(depth, "Announced NLRIs:\n");
  dump_nlris(&msg->announced_nlris, depth + 1);
}
