#include "parsebgp_mrt.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
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
      if (len - nread < sizeof(uint32_t)) {                                    \
        return PARSEBGP_PARTIAL_MSG;                                           \
      }                                                                        \
      memcpy(&(to), buf, sizeof(uint32_t));                                    \
      nread += sizeof(uint32_t);                                               \
      buf += sizeof(uint32_t);                                                 \
      break;                                                                   \
                                                                               \
    case PARSEBGP_BGP_AFI_IPV6:                                                \
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, to);                           \
      break;                                                                   \
                                                                               \
    default:                                                                   \
      return PARSEBGP_INVALID_MSG;                                             \
    }                                                                          \
  } while (0)

static parsebgp_error_t parse_table_dump(parsebgp_opts_t *opts,
                                         parsebgp_bgp_afi_t afi,
                                         parsebgp_mrt_table_dump_t *msg,
                                         uint8_t *buf, size_t *lenp,
                                         size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // View Number
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->view_number);
  msg->view_number = ntohs(msg->view_number);

  // Sequence
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->sequence);
  msg->sequence = ntohs(msg->sequence);

  // Prefix Address
  DESERIALIZE_IP(afi, buf, len, nread, msg->prefix);

  // Prefix Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->prefix_len);

  // Status (unused)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->status);

  // Originated Time
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->originated_time);
  msg->originated_time = ntohl(msg->originated_time);

  // Peer IP address
  DESERIALIZE_IP(afi, buf, len, nread, msg->peer_ip);

  // Peer ASN (2-byte only)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->peer_asn);
  msg->peer_asn = ntohs(msg->peer_asn);

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
  parsebgp_bgp_update_path_attrs_destroy(&msg->path_attrs);
}

static void dump_table_dump(parsebgp_bgp_afi_t afi,
                            parsebgp_mrt_table_dump_t *msg, int depth)
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
                               uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_mrt_table_dump_v2_peer_entry_t *pe = NULL;
  uint8_t u8;
  uint16_t u16;

  // Collector BGP ID
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->collector_bgp_id);

  // View Name Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->view_name_len);
  msg->view_name_len = ntohs(msg->view_name_len);
  if (msg->view_name_len > (len - nread)) {
    return PARSEBGP_PARTIAL_MSG;
  }

  // View Name
  if (msg->view_name_len > 0) {
    if ((msg->view_name = malloc(sizeof(char) * (msg->view_name_len + 1))) ==
        NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    memcpy(msg->view_name, buf, msg->view_name_len);
    msg->view_name[msg->view_name_len] = '\0';
    nread += msg->view_name_len;
    buf += msg->view_name_len;
  }

  // Peer Count
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->peer_count);
  msg->peer_count = ntohs(msg->peer_count);

  // allocate some space for the peer entries
  if ((msg->peer_entries = malloc_zero(
         sizeof(parsebgp_mrt_table_dump_v2_peer_entry_t) * msg->peer_count)) ==
      NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  // Peer Entries
  for (i = 0; i < msg->peer_count; i++) {
    pe = &msg->peer_entries[i];

    // Peer Type (discarded)
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);

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
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u16);
      pe->asn = ntohs(u16);
      break;

    case PARSEBGP_MRT_ASN_4_BYTE:
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, pe->asn);
      pe->asn = ntohl(pe->asn);
      break;

    default:
      return PARSEBGP_INVALID_MSG;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void
destroy_table_dump_v2_peer_index(parsebgp_mrt_table_dump_v2_peer_index_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->view_name);
  msg->view_name = NULL;
  msg->view_name_len = 0;

  free(msg->peer_entries);
  msg->peer_entries = NULL;
  msg->peer_count = 0;
}

static void
dump_table_dump_v2_peer_index(parsebgp_mrt_table_dump_v2_peer_index_t *msg,
                              int depth)
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
  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;
  parsebgp_error_t err;

  opts->bgp.asn_4_byte = 1;
  opts->bgp.mp_reach_no_afi_safi_reserved = 1;
  switch (subtype) {
  case RIB_IPV4_UNICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV4;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_UNICAST;
    break;

  case RIB_IPV4_MULTICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV4;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_MULTICAST;
    break;

  case RIB_IPV6_UNICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV6;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_UNICAST;
    break;

  case RIB_IPV6_MULTICAST:
    opts->bgp.afi = PARSEBGP_BGP_AFI_IPV6;
    opts->bgp.safi = PARSEBGP_BGP_SAFI_MULTICAST;
    break;

  default:
    // programming error
    assert(0);
    return PARSEBGP_INVALID_MSG;
  }

  for (i = 0; i < entry_count; i++) {
    entry = &entries[i];

    // Peer Index
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, entry->peer_index);
    entry->peer_index = ntohs(entry->peer_index);

    // Originated Time
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, entry->originated_time);
    entry->originated_time = ntohl(entry->originated_time);

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
  parsebgp_mrt_table_dump_v2_rib_entry_t *entries, uint16_t entry_count)
{
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;

  for (i = 0; i < entry_count; i++) {
    entry = &entries[i];

    parsebgp_bgp_update_path_attrs_destroy(&entry->path_attrs);
  }

  free(entries);
}

static parsebgp_error_t
parse_table_dump_v2_afi_safi_rib(parsebgp_opts_t *opts,
                                 parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                 parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg,
                                 uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Sequence Number
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->sequence);
  msg->sequence = ntohl(msg->sequence);

  // Prefix Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->prefix_len);

  // Prefix
  slen = len - nread;
  if ((err = parsebgp_decode_prefix(msg->prefix_len, msg->prefix, buf,
                                    &slen)) != PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  // Entry Count
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->entry_count);
  msg->entry_count = ntohs(msg->entry_count);

  // RIB Entries
  // allocate some memory for the entries
  if ((msg->entries = malloc(sizeof(parsebgp_mrt_table_dump_v2_rib_entry_t) *
                             msg->entry_count)) == NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }
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
  destroy_table_dump_v2_rib_entries(msg->entries, msg->entry_count);
  msg->entries = NULL;
  msg->entry_count = 0;
}

static void
dump_table_dump_v2_afi_safi_rib(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg,
                                int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_afi_safi_rib_t, depth);

  int afi = (subtype == RIB_IPV4_UNICAST || subtype == RIB_IPV4_MULTICAST)
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
  parsebgp_mrt_table_dump_v2_t *msg, uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t nread = 0;
  // table dump v2 has no common header, so just call the appropriate subtype
  // parser
  switch (subtype) {
  case PEER_INDEX_TABLE:
    return parse_table_dump_v2_peer_index(&msg->peer_index, buf, lenp, remain);
    break;

  case RIB_IPV4_UNICAST:
  case RIB_IPV6_UNICAST:
    return parse_table_dump_v2_afi_safi_rib(opts, subtype, &msg->afi_safi_rib,
                                            buf, lenp, remain);
    break;

  case RIB_IPV4_MULTICAST:
  case RIB_IPV6_MULTICAST:
  case RIB_GENERIC:
    // these probably aren't too hard to support (esp. multicast), but bgpdump
    // doesn't support them, so it likely means we don't have any actual use for
    // it.
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain,
                                  "Unsupported MRT TABLE_DUMP_V2 subtype (%d)",
                                  subtype);
    // only used if we try and skip the unknown data:
    *lenp = nread;
    return PARSEBGP_OK;
    break;

  default:
    return PARSEBGP_INVALID_MSG;
    break;
  }
}

static void destroy_table_dump_v2(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                  parsebgp_mrt_table_dump_v2_t *msg)
{
  // table dump v2 has no common header, so just call the appropriate subtype
  // destructor
  switch (subtype) {
  case PEER_INDEX_TABLE:
    return destroy_table_dump_v2_peer_index(&msg->peer_index);
    break;

  case RIB_IPV4_UNICAST:
  case RIB_IPV6_UNICAST:
    return destroy_table_dump_v2_afi_safi_rib(subtype, &msg->afi_safi_rib);
    break;

  case RIB_IPV4_MULTICAST:
  case RIB_IPV6_MULTICAST:
  case RIB_GENERIC:
  default:
    break;
  }
}

static void dump_table_dump_v2(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                               parsebgp_mrt_table_dump_v2_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_table_dump_v2_t, depth);

  switch (subtype) {
  case PEER_INDEX_TABLE:
    return dump_table_dump_v2_peer_index(&msg->peer_index, depth + 1);
    break;

  case RIB_IPV4_UNICAST:
  case RIB_IPV6_UNICAST:
    return dump_table_dump_v2_afi_safi_rib(subtype, &msg->afi_safi_rib,
                                           depth + 1);
    break;

  case RIB_IPV4_MULTICAST:
  case RIB_IPV6_MULTICAST:
  case RIB_GENERIC:
  default:
    break;
  }
}

static parsebgp_error_t parse_bgp4mp(parsebgp_opts_t *opts,
                                     parsebgp_mrt_bgp4mp_subtype_t subtype,
                                     parsebgp_mrt_bgp4mp_t *msg, uint8_t *buf,
                                     size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  uint16_t u16;
  parsebgp_error_t err;

  // ASN fields
  switch (subtype) {
  // 2-byte ASN subtypes:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
    // Peer ASN
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u16);
    msg->peer_asn = ntohs(u16);

    // Local ASN
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u16);
    msg->local_asn = ntohs(u16);
    break;

  // 4-byte ASN subtypes:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    // Peer ASN
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->peer_asn);
    msg->peer_asn = ntohl(msg->peer_asn);

    // Local ASN
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->local_asn);
    msg->local_asn = ntohl(msg->local_asn);
    break;

  default:
    return PARSEBGP_INVALID_MSG;
    break;
  }

  // Interface Index
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->interface_index);
  msg->interface_index = ntohs(msg->interface_index);

  // Address Family
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->afi);
  msg->afi = ntohs(msg->afi);

  // Peer IP
  DESERIALIZE_IP(msg->afi, buf, len, nread, msg->peer_ip);

  // Local IP
  DESERIALIZE_IP(msg->afi, buf, len, nread, msg->local_ip);

  // And then the actual data, based on the subtype
  // the _AS4 subtypes actually only change the common part of the message, so
  // we can treat them the same as their non-AS4 subtype at this point.
  switch (subtype) {
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
    // Old State
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->data.state_change.old_state);
    msg->data.state_change.old_state = ntohs(msg->data.state_change.old_state);

    // New State
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->data.state_change.new_state);
    msg->data.state_change.new_state = ntohs(msg->data.state_change.new_state);
    break;

  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    opts->bgp.asn_4_byte = 1;
  // FALL THROUGH

  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
  case PARSEBGP_MRT_BGP4MP_MESSAGE:
    slen = len - nread;
    if ((err = parsebgp_bgp_decode(opts, &msg->data.bgp_msg, buf, &slen)) !=
        PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    return PARSEBGP_INVALID_MSG;
    break;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void destroy_bgp4mp(parsebgp_mrt_bgp4mp_subtype_t subtype,
                           parsebgp_mrt_bgp4mp_t *msg)
{
  switch (subtype) {
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE:
  case PARSEBGP_MRT_BGP4MP_STATE_CHANGE_AS4:
    // no dynamic memory used
    break;

  case PARSEBGP_MRT_BGP4MP_MESSAGE:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    parsebgp_bgp_destroy_msg(&msg->data.bgp_msg);
    break;

  default:
    break;
  }
}

static void dump_bgp4mp(parsebgp_mrt_bgp4mp_subtype_t subtype,
                        parsebgp_mrt_bgp4mp_t *msg, int depth)
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
    parsebgp_bgp_dump_msg(&msg->data.bgp_msg, depth);
    break;

  default:
    break;
  }
}

static parsebgp_error_t parse_common_hdr(parsebgp_mrt_msg_t *msg, uint8_t *buf,
                                         size_t *lenp)
{
  size_t len = *lenp, nread = 0;

  // Timestamp
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->timestamp_sec);
  msg->timestamp_sec = ntohl(msg->timestamp_sec);

  // Type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->type);
  msg->type = ntohs(msg->type);

  // Sub-type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->subtype);
  msg->subtype = ntohs(msg->subtype);

  // Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->len);
  msg->len = ntohl(msg->len);
  if (msg->len > len - nread) {
    return PARSEBGP_PARTIAL_MSG;
  }

  // maybe parse the microsecond timestamp (also validates supported message
  // types)
  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->timestamp_usec);
    msg->timestamp_usec = ntohl(msg->timestamp_usec);
    break;

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
    return PARSEBGP_INVALID_MSG;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static void dump_common_hdr(parsebgp_mrt_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_INT(depth, "Timestamp.sec", msg->timestamp_sec);
  PARSEBGP_DUMP_INT(depth, "Type", msg->type);
  PARSEBGP_DUMP_INT(depth, "Subtype", msg->subtype);
  PARSEBGP_DUMP_INT(depth, "Length", msg->len);
  PARSEBGP_DUMP_INT(depth, "Timestamp.usec", msg->timestamp_usec);
}

parsebgp_error_t parsebgp_mrt_decode(parsebgp_opts_t *opts,
                                     parsebgp_mrt_msg_t *msg, uint8_t *buf,
                                     size_t *len)
{
  parsebgp_error_t err;
  size_t slen = 0, nread = 0, remain = 0;

  // First, parse the common header
  slen = *len;
  if ((err = parse_common_hdr(msg, buf, &slen)) != PARSEBGP_OK) {
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
    return PARSEBGP_INVALID_MSG;
  }
  if (remain > slen) {
    // we already know that the message will be longer than what we have in the
    // buffer, give up now
    return PARSEBGP_PARTIAL_MSG;
  }

  switch (msg->type) {

  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    err = parse_table_dump(opts, msg->subtype, &msg->types.table_dump,
                           buf + nread, &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    err = parse_table_dump_v2(opts, msg->subtype, &msg->types.table_dump_v2,
                              buf + nread, &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    err = parse_bgp4mp(opts, msg->subtype, &msg->types.bgp4mp, buf + nread,
                       &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "MRT Type %d not supported", msg->type);
    break;

  default:
    // unknown message type
    return PARSEBGP_INVALID_MSG;
  }
  if (err != PARSEBGP_OK) {
    return err;
  }
  nread += slen;

  assert(MRT_HDR_LEN + msg->len == nread);

  *len = nread;
  return PARSEBGP_OK;
}

void parsebgp_mrt_destroy_msg(parsebgp_mrt_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // common header has no dynamically allocated memory

  // free per-type memory
  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    destroy_table_dump(msg->subtype, &msg->types.table_dump);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    destroy_table_dump_v2(msg->subtype, &msg->types.table_dump_v2);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    destroy_bgp4mp(msg->subtype, &msg->types.bgp4mp);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    // not implemented
    break;
  }

  return;
}

void parsebgp_mrt_dump_msg(parsebgp_mrt_msg_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_mrt_msg_t, depth);
  dump_common_hdr(msg, depth);

  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    dump_table_dump(msg->subtype, &msg->types.table_dump, depth + 1);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    dump_table_dump_v2(msg->subtype, &msg->types.table_dump_v2, depth + 1);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    dump_bgp4mp(msg->subtype, &msg->types.bgp4mp, depth + 1);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
  case PARSEBGP_MRT_TYPE_OSPF_V2:
  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    break;
  }
}
