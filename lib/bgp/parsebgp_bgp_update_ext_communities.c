#include "parsebgp_bgp_update_ext_communities.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

parsebgp_error_t parsebgp_bgp_update_ext_communities_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_ext_communities_t *msg,
  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_bgp_update_ext_community_t *comm;

  // sanity check on the length
  if (remain % 8 != 0) {
    return PARSEBGP_INVALID_MSG;
  }

  msg->communities_cnt = remain / 8;

  PARSEBGP_MAYBE_REALLOC(msg->communities,
                         sizeof(parsebgp_bgp_update_ext_community_t),
                         msg->_communities_alloc_cnt, msg->communities_cnt);
  // TODO: does this really need to be zeroed?
  memset(msg->communities, 0,
         sizeof(parsebgp_bgp_update_ext_community_t) * msg->communities_cnt);

  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];

    // Type (High)
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->type);

    switch (comm->type) {
    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_TWO_OCTET_AS:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_TWO_OCTET_AS:
      // Sub-Type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // Global Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.two_octet.global_admin);
      comm->types.two_octet.global_admin =
        ntohs(comm->types.two_octet.global_admin);

      // Local Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.two_octet.local_admin);
      comm->types.two_octet.local_admin =
        ntohl(comm->types.two_octet.local_admin);
      break;

    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_IPV4:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_IPV4:
      // Sub-Type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // AFI
      comm->types.ip_addr.global_admin_ip_afi = PARSEBGP_BGP_AFI_IPV4;

      // Global Admin (IP Address)
      // manual copy since the destination can also hold v6 addr
      if ((len - nread) < 4) {
        return PARSEBGP_PARTIAL_MSG;
      }
      memcpy(comm->types.ip_addr.global_admin_ip, buf, 4);
      nread += 4;
      buf += 4;

      // Local Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.ip_addr.local_admin);
      comm->types.ip_addr.local_admin = ntohs(comm->types.ip_addr.local_admin);
      break;

    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_FOUR_OCTET_AS:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_FOUR_OCTET_AS:
      // Sub-Type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // Global Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.four_octet.global_admin);
      comm->types.four_octet.global_admin =
        ntohl(comm->types.four_octet.global_admin);

      // Local Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.four_octet.local_admin);
      comm->types.four_octet.local_admin =
        ntohs(comm->types.four_octet.local_admin);
      break;

    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_OPAQUE:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_OPAQUE:
      // Sub-Type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // Opaque (6 bytes)
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->types.opaque);
      break;

    default:
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->types.unknown);
      break;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t parsebgp_bgp_update_ext_communities_ipv6_decode(
  parsebgp_opts_t *opts, parsebgp_bgp_update_ext_communities_t *msg,
  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_bgp_update_ext_community_t *comm;

  // sanity check on the length
  if (remain % 20 != 0) {
    return PARSEBGP_INVALID_MSG;
  }

  msg->communities_cnt = remain / 20;

  PARSEBGP_MAYBE_REALLOC(msg->communities,
                         sizeof(parsebgp_bgp_update_ext_community_t),
                         msg->_communities_alloc_cnt, msg->communities_cnt);
  // TODO: does this really need to be zeroed?
  memset(msg->communities, 0,
         sizeof(parsebgp_bgp_update_ext_community_t) * msg->communities_cnt);

  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];

    // Type (High)
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->type);

    switch (comm->type) {

    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_IPV6:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_IPV6:
      // Sub-type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // AFI
      comm->types.ip_addr.global_admin_ip_afi = PARSEBGP_BGP_AFI_IPV6;

      // IPv6 Address
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.ip_addr.global_admin_ip);

      // Local Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.ip_addr.local_admin);
      comm->types.ip_addr.local_admin = ntohs(comm->types.ip_addr.local_admin);

    default:
      // this is an especially unusual error
      PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, 19,
                                    "Unknown IPv6 Extended Community Type (%d)",
                                    comm->type);
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_ext_communities_destroy(
  parsebgp_bgp_update_ext_communities_t *msg)
{
  if (msg == NULL) {
    return;
  }
  // currently no types have dynamic memory

  free(msg->communities);
  free(msg);
}

void parsebgp_bgp_update_ext_communities_clear(
  parsebgp_bgp_update_ext_communities_t *msg)
{
  msg->communities_cnt = 0;
}

static void dump_ext_community(parsebgp_bgp_update_ext_community_t *comm,
                               int depth)
{
  PARSEBGP_DUMP_INT(depth, "Type", comm->type);
  PARSEBGP_DUMP_INT(depth, "Subtype", comm->subtype);

  depth++;
  switch (comm->type) {
  case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_TWO_OCTET_AS:
  case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_TWO_OCTET_AS:
    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_ext_community_two_octet_t,
                             depth);
    PARSEBGP_DUMP_INT(depth, "Global Admin",
                      comm->types.two_octet.global_admin);
    PARSEBGP_DUMP_INT(depth, "Local Admin", comm->types.two_octet.local_admin);
    break;

  case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_IPV4:
  case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_IPV4:
    // v6 communities have the same type value:
    // case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_IPV6:
    // case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_IPV6:

    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_ext_community_ip_addr_t,
                             depth);
    PARSEBGP_DUMP_INT(depth, "Global Admin IP AFI",
                      comm->types.ip_addr.global_admin_ip_afi);
    PARSEBGP_DUMP_IP(depth, "Global Admin IP",
                     comm->types.ip_addr.global_admin_ip_afi,
                     comm->types.ip_addr.global_admin_ip);
    PARSEBGP_DUMP_INT(depth, "Local Admin", comm->types.ip_addr.local_admin);
    break;

  case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_FOUR_OCTET_AS:
  case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_FOUR_OCTET_AS:
    PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_ext_community_four_octet_t,
                             depth);
    PARSEBGP_DUMP_INT(depth, "Global Admin",
                      comm->types.four_octet.global_admin);
    PARSEBGP_DUMP_INT(depth, "Local Admin", comm->types.four_octet.local_admin);
    break;

  case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_OPAQUE:
  case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_OPAQUE:
    PARSEBGP_DUMP_DATA(depth, "Opaque Data", comm->types.opaque,
                       sizeof(comm->types.opaque));
    break;

  default:
    PARSEBGP_DUMP_INFO(depth, "Unknown Type\n");
    PARSEBGP_DUMP_DATA(depth, "Data", comm->types.unknown,
                       sizeof(comm->types.unknown));
    break;
  }
}

void parsebgp_bgp_update_ext_communities_dump(
  parsebgp_bgp_update_ext_communities_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_ext_communities_t, depth);

  PARSEBGP_DUMP_INT(depth, "Communities Count", msg->communities_cnt);

  int i;
  for (i = 0; i < msg->communities_cnt; i++) {
    dump_ext_community(&msg->communities[i], depth + 1);
  }
}
