#include "parsebgp_bgp_update_mp_reach.h"
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

static parsebgp_error_t
parse_afi_ipv4_ipv6_unicast_nlri(parsebgp_opts_t *opts,
                                 parsebgp_bgp_afi_t afi,
                                 parsebgp_bgp_prefix_t **nlris,
                                 int *nlris_cnt,
                                 uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  uint8_t p_type;
  parsebgp_bgp_prefix_t *tuple;
  parsebgp_error_t err;

  switch (afi) {
  case PARSEBGP_BGP_AFI_IPV4:
    p_type = PARSEBGP_BGP_PREFIX_UNICAST_IPV4;
    break;

  case PARSEBGP_BGP_AFI_IPV6:
    p_type = PARSEBGP_BGP_PREFIX_UNICAST_IPV6;
    break;

  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported AFI (%d)", afi);
  }

  *nlris = NULL;
  *nlris_cnt = 0;

  while ((remain - nread) > 0) {
    // optimistically allocate a new prefix tuple
    if ((*nlris = realloc(*nlris, sizeof(parsebgp_bgp_prefix_t) *
                                    ((*nlris_cnt) + 1))) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    tuple = &(*nlris)[*nlris_cnt];
    (*nlris_cnt)++;

    tuple->type = p_type;
    tuple->afi = afi;
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

    // DEBUG
    char ip_buf[INET6_ADDRSTRLEN];
    inet_ntop(afi == PARSEBGP_BGP_AFI_IPV4 ? AF_INET : AF_INET6, tuple->addr,
              ip_buf, INET6_ADDRSTRLEN);
    fprintf(stderr, "DEBUG: Prefix: %s/%d\n", ip_buf, tuple->len);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_next_hop_afi_ipv4_ipv6_unicast(parsebgp_bgp_update_mp_reach_t *msg,
                                     uint8_t *buf, size_t *lenp, size_t remain)
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
    return PARSEBGP_INVALID_MSG;
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

  // DEBUG
  char ip_buf[INET6_ADDRSTRLEN] = "";
  inet_ntop(msg->afi == PARSEBGP_BGP_AFI_IPV4 ? AF_INET : AF_INET6,
            msg->next_hop, ip_buf, INET6_ADDRSTRLEN);
  char ip2_buf[INET6_ADDRSTRLEN] = "";
  inet_ntop(msg->afi == PARSEBGP_BGP_AFI_IPV4 ? AF_INET : AF_INET6,
            msg->next_hop_ll, ip2_buf, INET6_ADDRSTRLEN);
  fprintf(stderr, "DEBUG: NH-Len: %d, Next-Hop: %s, Next-Hop-LL: %s\n",
          msg->next_hop_len, ip_buf, ip2_buf);
  fprintf(stderr, "DEBUG: remain: %d\n", (int)(remain - nread));

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_reach_afi_ipv4_ipv6(parsebgp_opts_t *opts,
                          parsebgp_bgp_update_mp_reach_t *msg, uint8_t *buf,
                          size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  if ((remain - nread) < msg->next_hop_len) {
    return PARSEBGP_INVALID_MSG;
  }
  if ((len - nread) < msg->next_hop_len) {
    return PARSEBGP_PARTIAL_MSG;
  }

  switch (msg->safi) {
  case PARSEBGP_BGP_SAFI_UNICAST:
    slen = len - nread;
    if ((err = parse_next_hop_afi_ipv4_ipv6_unicast(
           msg, buf, &slen, remain - nread)) != PARSEBGP_OK) {
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
    if ((err = parse_afi_ipv4_ipv6_unicast_nlri(opts, msg->afi, &msg->nlris,
                                                &msg->nlris_cnt, buf, &slen,
                                                remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_SAFI_MPLS:
    // TODO
  default:
    PARSEBGP_SKIP_NOT_IMPLEMENTED(opts, buf, nread, remain - nread,
                                  "Unsupported SAFI (%d)", msg->safi);
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

static parsebgp_error_t
parse_unreach_afi_ipv4_ipv6(parsebgp_opts_t *opts,
                            parsebgp_bgp_update_mp_unreach_t *msg, uint8_t *buf,
                            size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  slen = len - nread;

  switch (msg->safi) {
  case PARSEBGP_BGP_SAFI_UNICAST:
    // Parse the NLRIs
    if ((err = parse_afi_ipv4_ipv6_unicast_nlri(
           opts, msg->afi, &msg->withdrawn_nlris, &msg->withdrawn_nlris_cnt,
           buf, &slen, remain - nread)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
    break;

  case PARSEBGP_BGP_SAFI_MPLS:
    // TODO
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
                                    uint8_t *buf, size_t *lenp, size_t remain)
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
    fprintf(stderr, "DEBUG: Using MRT-provided AFI/SAFI\n");
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

  fprintf(stderr, "DEBUG: MP_REACH: AFI: %d, SAFI: %d\n", msg->afi, msg->safi);

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
  free(msg->nlris);
}

void parsebgp_bgp_update_mp_reach_dump(
  parsebgp_bgp_update_mp_reach_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_mp_reach_t, depth);

  PARSEBGP_DUMP_INT(depth, "AFI", msg->afi);
  PARSEBGP_DUMP_INT(depth, "SAFI", msg->safi);
  PARSEBGP_DUMP_INT(depth, "Next Hop Length", msg->next_hop_len);

  if (msg->safi != PARSEBGP_BGP_SAFI_UNICAST) {
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
                                      uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // AFI
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->afi);
  msg->afi = ntohs(msg->afi);

  // SAFI
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->safi);

  fprintf(stderr, "DEBUG: MP_UNREACH: AFI: %d, SAFI: %d\n", msg->afi, msg->safi);

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
  free(msg->withdrawn_nlris);
}

void parsebgp_bgp_update_mp_unreach_dump(
  parsebgp_bgp_update_mp_unreach_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_update_mp_unreach_t, depth);

  PARSEBGP_DUMP_INT(depth, "AFI", msg->afi);
  PARSEBGP_DUMP_INT(depth, "SAFI", msg->safi);

  if (msg->safi != PARSEBGP_BGP_SAFI_UNICAST) {
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
