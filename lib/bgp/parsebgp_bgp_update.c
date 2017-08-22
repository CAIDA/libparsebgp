#include "parsebgp_bgp_update.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// for inet_ntop
// TODO: remove
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

    // DEBUG
    char ip_buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, tuple->addr, ip_buf, INET6_ADDRSTRLEN);
    fprintf(stderr, "DEBUG: Prefix: %s/%d\n", ip_buf, tuple->len);
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

static parsebgp_error_t
parse_path_attr_as_path(int asn_4_byte,
                        parsebgp_bgp_update_as_path_t *msg, uint8_t *buf,
                        size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bgp_update_as_path_seg_t *seg;
  uint16_t u16;
  int i;

  msg->segs = NULL;
  msg->segs_cnt = 0;

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

    // allocate enough space to store the ASNs (we store as 4-byte regardless of
    // what the path encoding is)
    if ((seg->asns = malloc(sizeof(uint32_t) * seg->asns_cnt)) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }

    fprintf(stderr, "DEBUG: AS_PATH Segment Type: %d, # ASes: %d (AS4?: %d)\n",
            seg->type, seg->asns_cnt, asn_4_byte);
    fprintf(stderr, "DEBUG: ");

    // Segment ASNs
    for (i = 0; i < seg->asns_cnt; i++) {
      if (asn_4_byte) {
        PARSEBGP_DESERIALIZE_VAL(buf, len, nread, seg->asns[i]);
        seg->asns[i] = ntohl(seg->asns[i]);
      } else {
        PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u16);
        seg->asns[i] = ntohs(u16);
      }

      fprintf(stderr, "%"PRIu32" ", seg->asns[i]);
    }

    fprintf(stderr, "\n");
  }
  assert((remain - nread) == 0);

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_as_path(parsebgp_bgp_update_as_path_t *msg)
{
  int i;

  for (i = 0; i < msg->segs_cnt; i++) {
    free(msg->segs[i].asns);
  }
  free(msg->segs);
}

static parsebgp_error_t
parse_path_attr_next_hop(uint8_t *next_hop, uint8_t *buf,
                         size_t *lenp, size_t remain)
{
  size_t len = *lenp;

  // Next Hop IP (IPv4-only)
  if (len < sizeof(uint32_t)) {
    return PARSEBGP_PARTIAL_MSG;
  }
  if (remain < sizeof(uint32_t)) {
    return PARSEBGP_INVALID_MSG;
  }
  memcpy(next_hop, buf, sizeof(uint32_t));

  // DEBUG
  char ip_buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET, next_hop, ip_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: NEXT_HOP: %s\n", ip_buf);

  *lenp = sizeof(uint32_t);
  return PARSEBGP_OK;
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

  // Aggregator IP Address
  if (len < sizeof(uint32_t)) {
    return PARSEBGP_PARTIAL_MSG;
  }
  if (remain < sizeof(uint32_t)) {
    return PARSEBGP_INVALID_MSG;
  }
  memcpy(aggregator->addr, buf, sizeof(uint32_t));
  nread += sizeof(uint32_t);

  char ip_buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET, aggregator->addr, ip_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: AGGREGATOR: ASN: %" PRIu32 ", IP: %s (AS4? %d)\n",
          aggregator->asn, ip_buf, asn_4_byte);

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_path_attr_communities(parsebgp_bgp_update_communities_t *msg,
                            uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;

  msg->communities_cnt = remain / sizeof(uint32_t);

  if ((msg->communities = malloc(sizeof(uint32_t) * msg->communities_cnt)) ==
      NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  fprintf(stderr, "DEBUG: COMMUNITIES: Len: %d ", msg->communities_cnt);

  for (i = 0; i < msg->communities_cnt; i++) {
    if ((remain - nread) < sizeof(uint32_t)) {
      return PARSEBGP_INVALID_MSG;
    }
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->communities[i]);
    msg->communities[i] = ntohl(msg->communities[i]);

    fprintf(stderr, "%" PRIu16 ":%" PRIu16 " ",
            (uint16_t)(msg->communities[i] >> 16),
            (uint16_t)msg->communities[i]);
  }

  fprintf(stderr, "\n");

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_communities(parsebgp_bgp_update_communities_t *msg)
{
  free(msg->communities);
}

static parsebgp_error_t
parse_path_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg,
                             uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;

  msg->cluster_ids_cnt = remain / sizeof(uint32_t);

  if ((msg->cluster_ids =
         malloc(sizeof(uint32_t) * msg->cluster_ids_cnt)) == NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  fprintf(stderr, "DEBUG: CLUSTER_LIST: Len: %d ", msg->cluster_ids_cnt);

  for (i = 0; i < msg->cluster_ids_cnt; i++) {
    if ((remain - nread) < sizeof(uint32_t)) {
      return PARSEBGP_INVALID_MSG;
    }
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->cluster_ids[i]);
    msg->cluster_ids[i] = ntohl(msg->cluster_ids[i]);

    fprintf(stderr, "%"PRIu32" ", msg->cluster_ids[i]);
  }

  fprintf(stderr, "\n");

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_attr_cluster_list(parsebgp_bgp_update_cluster_list_t *msg)
{
  free(msg->cluster_ids);
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

  fprintf(stderr, "DEBUG: AS_PATHLIMIT: Max ASNs: %d, ASN: %"PRIu32"\n",
          msg->max_asns, msg->asn);

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

  fprintf(stderr, "DEBUG: LARGE_COMMUNITIES: Len: %d ", msg->communities_cnt);

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

    fprintf(stderr, "%" PRIu32 ":%" PRIu32 ":%" PRIu32 " ", comm->global_admin,
            comm->local_1, comm->local_2);
  }

  fprintf(stderr, "\n");

  *lenp = nread;
  return PARSEBGP_OK;
}

static void
destroy_attr_large_communities(parsebgp_bgp_update_large_communities_t *msg)
{
  free(msg->communities);
}

#define CHECK_REMAIN(remain, val)                                              \
  do {                                                                         \
    if (remain < sizeof(val)) {                                                \
      return PARSEBGP_INVALID_MSG;                                                      \
    };                                                                         \
  } while (0)

#define PARSE_SIMPLE_ATTR(name, val, buf, len, nread, remain)                  \
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
    fprintf(stderr, "DEBUG: " name ": %" PRIu64 "\n", (uint64_t)val);          \
  } while (0)

parsebgp_error_t parsebgp_bgp_update_path_attrs_decode(
  parsebgp_bgp_opts_t opts, parsebgp_bgp_update_path_attrs_t *path_attrs,
  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_bgp_update_path_attr_t *attr;
  uint8_t u8;
  parsebgp_error_t err = PARSEBGP_OK;

  path_attrs->attrs = NULL;
  path_attrs->attrs_cnt = 0;

  // Path Attributes Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, path_attrs->len);
  path_attrs->len = ntohs(path_attrs->len);
  fprintf(stderr, "DEBUG: BGP UPDATE: PA Len: %d (%d remain)\n",
          path_attrs->len, (int)(remain - nread));

  if (path_attrs->len > len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  if (path_attrs->len > remain) {
    return PARSEBGP_INVALID_MSG;
  }

  // read and realloc until we run out of attributes
  while (nread < path_attrs->len) {
    // optimistically allocate a new path attribute object
    if ((path_attrs->attrs =
           realloc(path_attrs->attrs, sizeof(parsebgp_bgp_update_path_attr_t) *
                   ((path_attrs->attrs_cnt) + 1))) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    attr = &path_attrs->attrs[path_attrs->attrs_cnt];
    memset(attr, 0, sizeof(*attr));
    path_attrs->attrs_cnt++;

    // Attribute Flags
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, attr->flags);

    // Attribute Type
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, attr->type);

    // Attribute Length
    if (attr->flags & PARSEBGP_BGP_PATH_ATTR_FLAG_EXTENDED) {
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, attr->len);
      attr->len = ntohs(attr->len);
    } else {
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);
      attr->len = u8;
    }

    if (attr->len > (remain - nread)) {
      return PARSEBGP_INVALID_MSG;
    }
    if (attr->len > (len - nread)) {
      return PARSEBGP_PARTIAL_MSG;
    }

    fprintf(
      stderr, "DEBUG: Path Attribute: Flags: %04x, Type: %d, Len: %d %s\n",
      attr->flags, attr->type, attr->len,
      (attr->flags & PARSEBGP_BGP_PATH_ATTR_FLAG_EXTENDED) ? "(EXT)" : "");

    slen = len - nread;
    switch (attr->type) {

      // Type 1:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
      PARSE_SIMPLE_ATTR("ORIGIN", attr->data.origin, buf, len, nread, remain);
      break;


      // Type 2:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS_PATH:
      if ((err = parse_path_attr_as_path(opts.asn_4_byte, &attr->data.as_path,
                                         buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 3:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
      if ((err = parse_path_attr_next_hop(attr->data.next_hop, buf, &slen,
                                          attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 4:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
      PARSE_SIMPLE_ATTR("MED", attr->data.med, buf, len, nread, remain);
      break;


      // Type 5:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
      PARSE_SIMPLE_ATTR("LOCAL_PREF", attr->data.local_pref, buf, len, nread,
                        remain);
      break;


      // Type 6:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
      // zero-length attr
      break;


      // Type 7
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AGGEGATOR:
      if ((err =
             parse_path_attr_aggregator(opts.asn_4_byte, &attr->data.aggregator,
                                        buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 8
    case PARSEBGP_BGP_PATH_ATTR_TYPE_COMMUNITIES:
      if ((err = parse_path_attr_communities(&attr->data.communities, buf,
                                             &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 9
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGINATOR_ID:
      PARSE_SIMPLE_ATTR("ORIGINATOR_ID", attr->data.originator_id, buf, len,
                        nread, remain);
      break;


      // Type 10
    case PARSEBGP_BGP_PATH_ATTR_TYPE_CLUSTER_LIST:
      if ((err = parse_path_attr_cluster_list(&attr->data.cluster_list, buf,
                                              &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      //...


      // Type 14
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_REACH_NLRI:
      if ((err = parsebgp_bgp_update_mp_reach_decode(
             opts, &attr->data.mp_reach, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 15
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MP_UNREACH_NLRI:
      if ((err = parsebgp_bgp_update_mp_unreach_decode(
             opts, &attr->data.mp_unreach, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 16
    case PARSEBGP_BGP_PATH_ATTR_TYPE_EXT_COMMUNITIES:
      if ((err = parsebgp_bgp_update_ext_communities_decode(
             &attr->data.ext_communities, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // Type 17
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AS4_PATH:
      // same as AS_PATH, but force 4-byte AS parsing
      if ((err = parse_path_attr_as_path(1, &attr->data.as_path, buf, &slen,
                                         attr->len)) != PARSEBGP_OK) {
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
      if ((err = parse_path_attr_as_pathlimit(&attr->data.as_pathlimit, buf,
                                              &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      //...


      // Type 25
    case PARSEBGP_BGP_PATH_ATTR_TYPE_IPV6_EXT_COMMUNITIES:
      if ((err = parsebgp_bgp_update_ext_communities_ipv6_decode(
             &attr->data.ext_communities, buf, &slen, attr->len)) != PARSEBGP_OK) {
        return err;
      }
      nread += slen;
      buf += slen;
      break;


      // ...


      // Type 29
    case PARSEBGP_BGP_PATH_ATTR_TYPE_BGP_LS:
      // TODO
      return PARSEBGP_NOT_IMPLEMENTED;
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
      // TODO: log message about unimplemented attribute and skip rather than
      // aborting.
      return PARSEBGP_NOT_IMPLEMENTED;
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

  for (i = 0; i < msg->attrs_cnt; i++) {
    attr = &msg->attrs[i];

    switch (attr->type) {

      // Types with no dynamic memory:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ORIGIN:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_NEXT_HOP:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_MED:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_LOCAL_PREF:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_ATOMIC_AGGREGATE:
    case PARSEBGP_BGP_PATH_ATTR_TYPE_AGGEGATOR:
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
      // TODO
      break;


    case PARSEBGP_BGP_PATH_ATTR_TYPE_LARGE_COMMUNITIES:
      destroy_attr_large_communities(&attr->data.large_communities);
      break;
    }
  }

  free(msg->attrs);
  msg->attrs = NULL;
  msg->attrs_cnt = 0;
}

parsebgp_error_t parsebgp_bgp_update_decode(parsebgp_bgp_opts_t opts,
                                            parsebgp_bgp_update_t *msg,
                                            uint8_t *buf, size_t *lenp,
                                            size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  parsebgp_error_t err;

  // Withdrawn Routes Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->withdrawn_nlris.len);
  msg->withdrawn_nlris.len = ntohs(msg->withdrawn_nlris.len);
  fprintf(stderr, "DEBUG: BGP UPDATE: Withdrawn Len: %d (%d remain)\n",
          msg->withdrawn_nlris.len, (int)(remain - nread));

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
  fprintf(stderr, "DEBUG: BGP UPDATE: NLRI Len: %d (%d remain)\n",
          msg->announced_nlris.len, (int)(remain - nread));
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
