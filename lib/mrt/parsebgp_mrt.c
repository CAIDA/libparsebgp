#include "parsebgp_mrt.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// for inet_ntop
// TODO remove
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/** Number of bytes in the MRT common header (excluding extended timestamp
    field) */
#define MRT_HDR_LEN 12

/** Helper to deserialize an IP address into a 16-byte buffer ('to') based on
    provided AFI */
#define DESERIALIZE_IP(afi, buf, len, nread, to)                               \
  do {                                                                         \
    switch ((afi)) {                                                           \
    case PARSEBGP_MRT_AFI_IPV4:                                                \
      if (len - nread < sizeof(uint32_t)) {                                    \
        return INCOMPLETE_MSG;                                                 \
      }                                                                        \
      memcpy(&(to), buf, sizeof(uint32_t));                                    \
      nread += sizeof(uint32_t);                                               \
      buf += sizeof(uint32_t);                                                 \
      break;                                                                   \
                                                                               \
    case PARSEBGP_MRT_AFI_IPV6:                                                \
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, to);                           \
      break;                                                                   \
                                                                               \
    default:                                                                   \
      return INVALID_MSG;                                                      \
    }                                                                          \
  } while (0)

static parsebgp_error_t parse_table_dump(parsebgp_mrt_afi_t afi,
                                         parsebgp_mrt_table_dump_t *msg,
                                         uint8_t *buf, size_t *lenp,
                                         size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;
  parsebgp_bgp_opts_t opts = {0};

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

  fprintf(stderr, "DEBUG: View: %d, Sequence: %d\n", msg->view_number,
          msg->sequence);
  int mapping[] = {-1, AF_INET, AF_INET6};
  char ip_buf[INET6_ADDRSTRLEN];
  inet_ntop(mapping[afi], msg->prefix, ip_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: Prefix: %s/%d\n", ip_buf, msg->prefix_len);
  fprintf(stderr, "DEBUG: Status: %d, Time: %" PRIu32 "\n", msg->status,
          msg->originated_time);
  inet_ntop(mapping[afi], msg->peer_ip, ip_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: Peer IP: %s, Peer ASN: %d\n", ip_buf, msg->peer_asn);
  fprintf(stderr, "DEBUG: Remain: %d, nread: %d\n", (int)remain, (int)nread);

  // Path Attributes
  slen = len - nread;
  if ((err = parsebgp_bgp_update_path_attrs_decode(
         opts, &msg->path_attrs, buf, &slen, remain - nread)) != OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  *lenp = nread;
  return OK;
}

static void destroy_table_dump(parsebgp_mrt_afi_t afi,
                               parsebgp_mrt_table_dump_t *msg)
{
  // TODO: destroy the attribute(s)
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
    return INCOMPLETE_MSG;
  }

  // View Name
  if (msg->view_name_len > 0) {
    if ((msg->view_name = malloc(sizeof(char) * (msg->view_name_len + 1))) ==
        NULL) {
      return MALLOC_FAILURE;
    }
    memcpy(msg->view_name, buf, msg->view_name_len);
    msg->view_name[msg->view_name_len] = '\0';
    nread += msg->view_name_len;
    buf += msg->view_name_len;
  }

  // Peer Count
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->peer_count);
  msg->peer_count = ntohs(msg->peer_count);

  fprintf(stderr, "DEBUG: Peer Index Table\n");
  fprintf(stderr, "DEBUG: Collector ID: %x\n", *(uint32_t*)msg->collector_bgp_id);
  fprintf(stderr, "DEBUG: View Name (len: %d): %s\n", msg->view_name_len,
          msg->view_name == NULL ? "" : msg->view_name);
  fprintf(stderr, "DEBUG: Peers (%d)\n", msg->peer_count);

  // allocate some space for the peer entries
  if ((msg->peer_entries = malloc_zero(
         sizeof(parsebgp_mrt_table_dump_v2_peer_entry_t) * msg->peer_count)) ==
      NULL) {
    return MALLOC_FAILURE;
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
      return INVALID_MSG;
    }

    fprintf(stderr, "DEBUG: -------------------- %d\n", i);
    fprintf(stderr, "DEBUG: Peer ASN Type: %d, Peer IP AFI: %d\n", pe->asn_type,
            pe->ip_afi);
    fprintf(stderr, "DEBUG: Peer BGP ID: %x\n", *(uint32_t*)pe->bgp_id);
    int mapping[] = {-1, AF_INET, AF_INET6};
    char ip_buf[INET6_ADDRSTRLEN];
    inet_ntop(mapping[pe->ip_afi], pe->ip, ip_buf, INET6_ADDRSTRLEN);
    fprintf(stderr, "DEBUG: Peer IP: %s, ASN: %"PRIu32"\n", ip_buf, pe->asn);
  }

  fprintf(stderr, "DEBUG: Len %d, Remain: %d, nread: %d\n", (int)len,
          (int)remain, (int)nread);

  *lenp = nread;
  return OK;
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

static parsebgp_error_t
parse_table_dump_v2_rib_entries(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                                parsebgp_mrt_table_dump_v2_rib_entry_t *entries,
                                uint16_t entry_count, uint8_t *buf,
                                size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;
  parsebgp_bgp_opts_t opts = {0};
  parsebgp_error_t err;

  opts.asn_4_byte = 1;
  opts.mp_reach_no_afi_safi_reserved = 1;
  switch (subtype) {
  case RIB_IPV4_UNICAST:
    opts.afi = PARSEBGP_BGP_AFI_IPV4;
    opts.safi = PARSEBGP_BGP_SAFI_UNICAST;
    break;

  case RIB_IPV4_MULTICAST:
    opts.afi = PARSEBGP_BGP_AFI_IPV4;
    opts.safi = PARSEBGP_BGP_SAFI_MULTICAST;
    break;

  case RIB_IPV6_UNICAST:
    opts.afi = PARSEBGP_BGP_AFI_IPV6;
    opts.safi = PARSEBGP_BGP_SAFI_UNICAST;
    break;

  case RIB_IPV6_MULTICAST:
    opts.afi = PARSEBGP_BGP_AFI_IPV6;
    opts.safi = PARSEBGP_BGP_SAFI_MULTICAST;
    break;

  default:
    // programming error
    assert(0);
    return INVALID_MSG;
  }

  for (i = 0; i < entry_count; i++) {
    entry = &entries[i];

    // Peer Index
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, entry->peer_index);
    entry->peer_index = ntohs(entry->peer_index);

    // Originated Time
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, entry->originated_time);
    entry->originated_time = ntohl(entry->originated_time);

    fprintf(stderr, "DEBUG: RIB ENTRY -------------------- %d\n", i);
    fprintf(stderr, "DEBUG: Peer Index: %d, Time: %" PRIu32 "\n",
            entry->peer_index, entry->originated_time);

    // Path Attributes
    slen = len - nread;
    if ((err = parsebgp_bgp_update_path_attrs_decode(
           opts, &entry->path_attrs, buf, &slen, remain - nread)) != OK) {
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return OK;
}

static void destroy_table_dump_v2_rib_entries(
  parsebgp_mrt_table_dump_v2_rib_entry_t *entries, uint16_t entry_count)
{
  int i;
  parsebgp_mrt_table_dump_v2_rib_entry_t *entry;

  for (i = 0; i < entry_count; i++) {
    entry = &entries[i];
    // TODO: destroy the BGP attributes
  }

  free(entries);
}

static parsebgp_error_t
parse_table_dump_v2_afi_safi_rib(parsebgp_mrt_table_dump_v2_subtype_t subtype,
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
                                    &slen)) != OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  // Entry Count
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->entry_count);
  msg->entry_count = ntohs(msg->entry_count);

  fprintf(stderr, "DEBUG: AFI/SAFI RIB Sequence Number: %d\n", msg->sequence);
  int mapping[] = {-1, AF_INET, AF_INET6};
  char ip_buf[INET6_ADDRSTRLEN];
  int afi = (subtype == RIB_IPV4_UNICAST || subtype == RIB_IPV4_MULTICAST)
              ? PARSEBGP_MRT_AFI_IPV4
              : PARSEBGP_MRT_AFI_IPV6;
  inet_ntop(mapping[afi], msg->prefix, ip_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: Prefix: %s/%d, Entry Count: %d\n",
          ip_buf, msg->prefix_len, msg->entry_count);

  // RIB Entries
  // allocate some memory for the entries
  if ((msg->entries = malloc(sizeof(parsebgp_mrt_table_dump_v2_rib_entry_t) *
                             msg->entry_count)) == NULL) {
    return MALLOC_FAILURE;
  }
  // and then parse the entries
  slen = len - nread;
  if ((err = parse_table_dump_v2_rib_entries(subtype, msg->entries,
                                             msg->entry_count, buf, &slen,
                                             (remain - nread))) != OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  *lenp = nread;
  return OK;
}

static void destroy_table_dump_v2_afi_safi_rib(
  parsebgp_mrt_table_dump_v2_subtype_t subtype,
  parsebgp_mrt_table_dump_v2_afi_safi_rib_t *msg)
{
  destroy_table_dump_v2_rib_entries(msg->entries, msg->entry_count);
  msg->entries = NULL;
  msg->entry_count = 0;
}

static parsebgp_error_t
parse_table_dump_v2(parsebgp_mrt_table_dump_v2_subtype_t subtype,
                    parsebgp_mrt_table_dump_v2_t *msg, uint8_t *buf,
                    size_t *lenp, size_t remain)
{
  // table dump v2 has no common header, so just call the appropriate subtype
  // parser
  switch (subtype) {
  case PEER_INDEX_TABLE:
    return parse_table_dump_v2_peer_index(&msg->peer_index, buf, lenp, remain);
    break;

  case RIB_IPV4_UNICAST:
  case RIB_IPV6_UNICAST:
    return parse_table_dump_v2_afi_safi_rib(subtype, &msg->afi_safi_rib, buf,
                                            lenp, remain);
    break;

  case RIB_IPV4_MULTICAST:
  case RIB_IPV6_MULTICAST:
  case RIB_GENERIC:
    // these probably aren't too hard to support (esp. multicast), but bgpdump
    // doesn't support them, so it likely means we don't have any actual use for
    // it.
    return NOT_IMPLEMENTED;
    break;

  default:
    return INVALID_MSG;
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

static parsebgp_error_t parse_bgp4mp(parsebgp_mrt_bgp4mp_subtype_t subtype,
                                     parsebgp_mrt_bgp4mp_t *msg,
                                     uint8_t *buf, size_t *lenp,
                                     size_t remain)
{
  size_t len = *lenp, nread = 0, slen = 0;
  uint16_t u16;
  parsebgp_error_t err;
  parsebgp_bgp_opts_t opts = {0};

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
    return INVALID_MSG;
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

  fprintf(stderr, "DEBUG: BGP4MP Message with subtype %d\n", subtype);
  fprintf(stderr, "DEBUG: Peer ASN: %"PRIu32", Local ASN: %"PRIu32"\n",
          msg->peer_asn, msg->local_asn);
  fprintf(stderr, "DEBUG: Interface Index: %d, AFI: %d\n", msg->interface_index,
          msg->afi);
  int mapping[] = {-1, AF_INET, AF_INET6};
  char peer_buf[INET6_ADDRSTRLEN];
  inet_ntop(mapping[msg->afi], msg->peer_ip, peer_buf, INET6_ADDRSTRLEN);
  char local_buf[INET6_ADDRSTRLEN];
  inet_ntop(mapping[msg->afi], msg->local_ip, local_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: Peer IP: %s, Local IP: %s\n", peer_buf, local_buf);

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

    fprintf(stderr, "DEBUG: Old State: %d, New State: %d\n",
            msg->data.state_change.old_state, msg->data.state_change.new_state);
    break;

  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4:
  case PARSEBGP_MRT_BGP4MP_MESSAGE_AS4_LOCAL:
    opts.asn_4_byte = 1;
    // FALL THROUGH

  case PARSEBGP_MRT_BGP4MP_MESSAGE_LOCAL:
  case PARSEBGP_MRT_BGP4MP_MESSAGE:
    slen = len - nread;
    if ((err = parsebgp_bgp_decode(opts, &msg->data.bgp_msg, buf, &slen)) !=
        OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  default:
    return INVALID_MSG;
    break;
  }

  *lenp = nread;
  return OK;
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
    // TODO: destroy the BGP message
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
    return INCOMPLETE_MSG;
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
    return INVALID_MSG;
  }

  *lenp = nread;
  return OK;
}

parsebgp_error_t parsebgp_mrt_decode(parsebgp_mrt_msg_t *msg,
                                     uint8_t *buf, size_t *len)
{
  parsebgp_error_t err;
  size_t slen = 0, nread = 0, remain = 0;

  // First, parse the common header
  slen = *len;
  if ((err = parse_common_hdr(msg, buf, &slen)) != OK) {
    return err;
  }
  nread += slen;

  fprintf(stderr, "DEBUG: Got MRT message with timestamp %" PRIu32 "\n",
          msg->timestamp_sec);
  fprintf(stderr, "DEBUG: Type: %d, Subtype: %d\n", msg->type, msg->subtype);
  fprintf(stderr, "DEBUG: Length: %"PRIu32"\n", msg->len);
  fprintf(stderr, "DEBUG: Timestamp.usec: %"PRIu32"\n", msg->timestamp_usec);

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
    return INVALID_MSG;
  }
  if (remain > slen) {
    // we already know that the message will be longer than what we have in the
    // buffer, give up now
    return INCOMPLETE_MSG;
  }

  fprintf(stderr, "DEBUG: Remain: %d\n", (int)remain);

  switch (msg->type) {
  case PARSEBGP_MRT_TYPE_OSPF_V2:
    return NOT_IMPLEMENTED;
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP:
    err = parse_table_dump(msg->subtype, &msg->types.table_dump, buf + nread,
                           &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_TABLE_DUMP_V2:
    err = parse_table_dump_v2(msg->subtype, &msg->types.table_dump_v2,
                              buf + nread, &slen, remain);
    break;

  case PARSEBGP_MRT_TYPE_BGP4MP:
  case PARSEBGP_MRT_TYPE_BGP4MP_ET:
    err = parse_bgp4mp(msg->subtype, &msg->types.bgp4mp, buf + nread, &slen,
                       remain);
    break;

  case PARSEBGP_MRT_TYPE_ISIS:
  case PARSEBGP_MRT_TYPE_ISIS_ET:
    return NOT_IMPLEMENTED;
    break;

  case PARSEBGP_MRT_TYPE_OSPF_V3:
  case PARSEBGP_MRT_TYPE_OSPF_V3_ET:
    return NOT_IMPLEMENTED;
    break;

  default:
    // unknown message type
    return INVALID_MSG;
  }
  if (err != OK) {
    return err;
  }
  nread += slen;

  fprintf(stderr, "DEBUG: hdr len: %d, msg->len: %d, nread: %d\n", MRT_HDR_LEN,
          (int)msg->len, (int)nread);
  assert(MRT_HDR_LEN + msg->len == nread);

  *len = nread;
  return OK;
}

void parsebgp_mrt_destroy_msg(parsebgp_mrt_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // common header has no dynamically allocated memory

  // free per-type memory
  switch(msg->type) {
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
