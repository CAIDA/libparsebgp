#include "parsebgp_bgp.h"
#include "parsebgp_bgp_open.h"
#include "parsebgp_bgp_update.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BGP_HDR_LEN 19

static parsebgp_error_t parse_common_hdr(parsebgp_bgp_msg_t *msg,
                                         uint8_t *buf, size_t *lenp)
{
  size_t len = *lenp, nread = 0;

  // Marker
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->marker);

  // Length
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->len);
  msg->len = ntohs(msg->len);

  // Type
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->type);

  *lenp = nread;
  return OK;
}

parsebgp_error_t parsebgp_bgp_decode(parsebgp_bgp_opts_t opts,
                                     parsebgp_bgp_msg_t *msg,
                                     uint8_t *buf, size_t *len)
{
  parsebgp_error_t err;
  size_t slen = 0, nread = 0, remain = 0;

  /* First, parse the message header */
  slen = *len;
  if ((err = parse_common_hdr(msg, buf, &slen)) != OK) {
    return err;
  }
  nread += slen;
  buf += slen;
  assert(nread == BGP_HDR_LEN);
  remain = msg->len - nread; // number of bytes left in the message
  slen = *len - nread; // number of bytes left in the buffer

  if (remain > slen) {
    // we already know that the message will be longer than what we have in the
    // buffer, give up now
    return INCOMPLETE_MSG;
  }

  fprintf(stderr, "DEBUG: BGP Message Type: %d, Len: %d\n", msg->type,
          msg->len);

  switch(msg->type) {
  case PARSEBGP_BGP_TYPE_OPEN:
    err =
      parsebgp_bgp_open_decode(opts, &msg->types.open, buf, &slen, remain);
    break;

  case PARSEBGP_BGP_TYPE_UPDATE:
    err =
      parsebgp_bgp_update_decode(opts, &msg->types.update, buf, &slen, remain);
    break;

  case PARSEBGP_BGP_TYPE_NOTIFICATION:
    // TODO
    return NOT_IMPLEMENTED;
    break;

  case PARSEBGP_BGP_TYPE_KEEPALIVE:
    // no data
    err = OK;
    slen = 0;
    break;

  case PARSEBGP_BGP_TYPE_ROUTE_REFRESH:
    // TODO
    return NOT_IMPLEMENTED;
    break;

  default:
    break;
  }
  if (err != OK) {
    // parser failed
    return err;
  }
  nread += slen;

  assert(msg->len == nread);
  *len = nread;
  return OK;
}

void parsebgp_bgp_destroy_msg(parsebgp_bgp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  // no dynamic memory in common header

  // destroy based on message type
  switch(msg->type) {
  case PARSEBGP_BGP_TYPE_OPEN:
    parsebgp_bgp_open_destroy(&msg->types.open);
    break;

  case PARSEBGP_BGP_TYPE_UPDATE:
    parsebgp_bgp_update_destroy(&msg->types.update);
    break;

  case PARSEBGP_BGP_TYPE_NOTIFICATION:
    // TODO
    break;

  case PARSEBGP_BGP_TYPE_KEEPALIVE:
    // TODO
    break;

  case PARSEBGP_BGP_TYPE_ROUTE_REFRESH:
    // TODO
    break;

  default:
    break;
  }
}
