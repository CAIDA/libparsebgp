#include "parsebgp_bgp_open.h"
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

parsebgp_error_t parse_capabilities(parsebgp_opts_t opts,
                                    parsebgp_bgp_open_t *msg,
                                    uint8_t *buf, size_t *lenp,
                                    size_t remain)
{
  size_t len = *lenp, nread = 0;
  parsebgp_bgp_open_capability_t *cap;

  while ((remain - nread) > 0) {
    if ((msg->capabilities =
           realloc(msg->capabilities, sizeof(parsebgp_bgp_open_capability_t) *
                                        (msg->capabilities_cnt + 1))) == NULL) {
      return PARSEBGP_MALLOC_FAILURE;
    }
    cap = &msg->capabilities[msg->capabilities_cnt++];

    // Code
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->code);

    // Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->len);

    // process data based on the code
    switch (cap->code) {

    case PARSEBGP_BGP_OPEN_CAPABILITY_MPBGP:
      if (cap->len != 4) {
        return PARSEBGP_INVALID_MSG;
      }
      // AFI
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.mpbgp.afi);
      cap->values.mpbgp.afi = ntohs(cap->values.mpbgp.afi);

      // Reserved
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.mpbgp.reserved);

      // SAFI
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.mpbgp.safi);

      fprintf(stderr, "DEBUG: MPBGP: AFI: %d, SAFI: %d, Reserved: %d\n",
              cap->values.mpbgp.afi, cap->values.mpbgp.safi,
              cap->values.mpbgp.reserved);
      break;

    case PARSEBGP_BGP_OPEN_CAPABILITY_AS4:
      if (cap->len != 4) {
        return PARSEBGP_INVALID_MSG;
      }
      PARSEBGP_DESERIALIZE_VAL(buf, len, nread, cap->values.asn);
      cap->values.asn = ntohl(cap->values.asn);
      fprintf(stderr, "DEBUG: AS4: %"PRIu32"\n", cap->values.asn);
      break;

    // capabilities with data that we are ignoring (since OpenBMP is ignoring
    // it)
    case PARSEBGP_BGP_OPEN_CAPABILITY_OUTBOUND_FILTER:
    case PARSEBGP_BGP_OPEN_CAPABILITY_GRACEFUL_RESTART:
    case PARSEBGP_BGP_OPEN_CAPABILITY_MULTI_SESSION:
      fprintf(stderr,
              "DEBUG: Capability %d found (skipping %d value bytes)\n",
              cap->code, cap->len);
      nread += cap->len;
      break;

      // capabilities with no extra data:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_ENHANCED:
    case PARSEBGP_BGP_OPEN_CAPABILITY_ROUTE_REFRESH_OLD:
      if (cap->len != 0) {
        fprintf(stderr,
                "ERROR: Expecting no extra data for BGP OPEN capability %d, "
                "but found %d bytes\n",
                cap->code, cap->len);
        return PARSEBGP_INVALID_MSG;
      }
      fprintf(stderr, "DEBUG: Capability %d found\n", cap->code);
      break;

    default:
      fprintf(stderr,
              "DEBUG: OPEN Capability %d is either unknown or currently "
              "unsupported\n",
              cap->code);
      return PARSEBGP_NOT_IMPLEMENTED;
      break;
    }
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t parse_params(parsebgp_opts_t opts,
                              parsebgp_bgp_open_t *msg,
                              uint8_t *buf, size_t *lenp,
                              size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;
  uint8_t u8;

  msg->capabilities = NULL;
  msg->capabilities_cnt = 0;

  while ((remain - nread) > 0) {
    // Ensure this is a capabilities parameter
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);
    if (u8 != 2) {
      fprintf(stderr,
              "ERROR: Unsupported BGP OPEN parameter type (%d). Only the "
              "Capabilities parameter (Type 2) is supported\n",
              u8);
      return PARSEBGP_NOT_IMPLEMENTED;
    }

    // Capabilities Length
    PARSEBGP_DESERIALIZE_VAL(buf, len, nread, u8);

    fprintf(stderr, "DEBUG: Parsing capabilities parameter of length %d\n", u8);

    // parse this capabilities parameter
    slen = len - nread;
    if ((err = parse_capabilities(opts, msg, buf, &slen, u8)) != PARSEBGP_OK) {
      return err;
    }
    nread += slen;
    buf += slen;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

parsebgp_error_t parsebgp_bgp_open_decode(parsebgp_opts_t opts,
                                          parsebgp_bgp_open_t *msg,
                                          uint8_t *buf, size_t *lenp,
                                          size_t remain)
{
  size_t len = *lenp, nread = 0, slen;
  parsebgp_error_t err;

  // Version
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->version);

  // ASN
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->asn);
  msg->asn = ntohs(msg->asn);

  // Hold Time
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->hold_time);
  msg->hold_time = ntohs(msg->hold_time);

  // BGP ID
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->bgp_id);
  msg->bgp_id = ntohl(msg->bgp_id);

  // Parameters Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->param_len);

  fprintf(stderr,
          "DEBUG: BGP OPEN: Version: %d, ASN: %d, Hold Time: %d, BGP ID: %x, "
          "Params Len: %d\n",
          msg->version, msg->asn, msg->hold_time, msg->bgp_id, msg->param_len);

  // no params
  if (msg->param_len == 0) {
    *lenp = nread;
    return PARSEBGP_OK;
  }

  // Parse the capabilities
  slen = len - nread;
  if ((err = parse_params(opts, msg, buf, &slen, (remain - nread))) !=
      PARSEBGP_OK) {
    return err;
  }
  nread += slen;
  buf += slen;

  if (nread != remain) {
    fprintf(stderr, "ERROR: Trailing data after OPEN Capabilities.\n");
    return PARSEBGP_NOT_IMPLEMENTED;
  }

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_open_destroy(parsebgp_bgp_open_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // we don't (currently) have any capabilities that use dynamic memory, so for
  // now just free the capabilities array
  free(msg->capabilities);
}
