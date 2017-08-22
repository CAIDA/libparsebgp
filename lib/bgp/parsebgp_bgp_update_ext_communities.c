#include "parsebgp_bgp_update_ext_communities.h"
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

parsebgp_error_t parsebgp_bgp_update_ext_communities_decode(
  parsebgp_bgp_update_ext_communities_t *msg, uint8_t *buf, size_t *lenp,
  size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_bgp_update_ext_community_t *comm;

  // sanity check on the length
  if (remain % 8 != 0) {
    return PARSEBGP_INVALID_MSG;
  }

  msg->communities_cnt = remain / 8;

  if ((msg->communities = malloc_zero(
         sizeof(parsebgp_bgp_update_ext_community_t) * msg->communities_cnt)) ==
      NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  fprintf(stderr, "DEBUG: EXTENDED COMMUNITIES: Cnt: %d\n",
          msg->communities_cnt);

  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];

    // Type (High)
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->type);

    fprintf(stderr, "DEBUG: EXT_COMM: Type (High): 0x%02x\n", comm->type);

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

      fprintf(stderr,
              "DEBUG: TWO-OCTET: Subtype: %02x, Global Admin: %" PRIu16
              ", Local Admin: %" PRIu32 "\n",
              comm->subtype, comm->types.two_octet.global_admin,
              comm->types.two_octet.local_admin);
      break;

    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_IPV4:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_IPV4:
      // Sub-Type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

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

      char ip_buf[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET, comm->types.ip_addr.global_admin_ip, ip_buf,
                INET6_ADDRSTRLEN);
      fprintf(
        stderr,
        "DEBUG: IPv4: Subtype: %02x, Global Admin: %s, Local Admin: %" PRIu32
        "\n",
        comm->subtype, ip_buf, comm->types.ip_addr.local_admin);
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

      fprintf(stderr,
              "DEBUG: FOUR-OCTET: Subtype: %02x, Global Admin: %" PRIu32
              ", Local Admin: %" PRIu16 "\n",
              comm->subtype, comm->types.four_octet.global_admin,
              comm->types.four_octet.local_admin);
      break;

    case PARSEBGP_BGP_EXT_COMM_TYPE_TRANS_OPAQUE:
    case PARSEBGP_BGP_EXT_COMM_TYPE_NONTRANS_OPAQUE:
      // Sub-Type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // Opaque (6 bytes)
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->types.opaque);

      fprintf(stderr, "DEBUG: OPAQUE: Subtype: %02x\n", comm->subtype);
      break;

    default:
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->types.unknown);
      fprintf(stderr, "DEBUG: UNKNOWN COMMUNITY\n");
      break;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t parsebgp_bgp_update_ext_communities_ipv6_decode(
  parsebgp_bgp_update_ext_communities_t *msg, uint8_t *buf, size_t *lenp,
  size_t remain)
{
  size_t len = *lenp, nread = 0;
  int i;
  parsebgp_bgp_update_ext_community_t *comm;

  // sanity check on the length
  if (remain % 20 != 0) {
    return PARSEBGP_INVALID_MSG;
  }

  msg->communities_cnt = remain / 20;

  if ((msg->communities = malloc_zero(
         sizeof(parsebgp_bgp_update_ext_community_t) * msg->communities_cnt)) ==
      NULL) {
    return PARSEBGP_MALLOC_FAILURE;
  }

  fprintf(stderr, "DEBUG: EXTENDED COMMUNITIES: Cnt: %d\n",
          msg->communities_cnt);

  for (i = 0; i < msg->communities_cnt; i++) {
    comm = &msg->communities[i];

    // Type (High)
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->type);

    fprintf(stderr, "DEBUG: EXT_COMM: Type (High): 0x%02x\n", comm->type);

    switch (comm->type) {

    case PARSEBGP_BGP_IPV6_EXT_COMM_TYPE_TRANS_IPV6:
    case PARSEBGP_BGP_IPV6_EXT_COMM_TYPE_NONTRANS_IPV6:
      // Sub-type
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, comm->subtype);

      // IPv6 Address
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.ip_addr.global_admin_ip);

      // Local Admin
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread,
                               comm->types.ip_addr.local_admin);
      comm->types.ip_addr.local_admin = ntohs(comm->types.ip_addr.local_admin);

      char ip_buf[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, comm->types.ip_addr.global_admin_ip, ip_buf,
                INET6_ADDRSTRLEN);
      fprintf(
        stderr,
        "DEBUG: IPv4: Subtype: %02x, Global Admin: %s, Local Admin: %" PRIu32
        "\n",
        comm->subtype, ip_buf, comm->types.ip_addr.local_admin);

    default:
      return PARSEBGP_NOT_IMPLEMENTED;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_update_ext_communities_destroy(
  parsebgp_bgp_update_ext_communities_t *msg)
{
  // currently no types have dynamic memory

  free(msg->communities);
}
