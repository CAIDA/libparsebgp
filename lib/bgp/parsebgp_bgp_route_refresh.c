#include "parsebgp_bgp_route_refresh.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

parsebgp_error_t
parsebgp_bgp_route_refresh_decode(parsebgp_opts_t *opts,
                                  parsebgp_bgp_route_refresh_t *msg,
                                  uint8_t *buf, size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;

  // AFI
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->afi);
  msg->afi = ntohs(msg->afi);

  // Subtype (Reserved)
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->subtype);

  // SAFI
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->safi);

  // Data
  msg->data_len = remain - nread;
  if ((len - nread) < msg->data_len) {
    return PARSEBGP_PARTIAL_MSG;
  }
  PARSEBGP_MAYBE_REALLOC(msg->data, sizeof(uint8_t), msg->_data_alloc_len,
                         msg->data_len);
  memcpy(msg->data, buf, msg->data_len);
  nread += msg->data_len;

  *lenp = nread;
  return PARSEBGP_OK;
}

void parsebgp_bgp_route_refresh_destroy(parsebgp_bgp_route_refresh_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->data);

  free(msg);
}

void parsebgp_bgp_route_refresh_clear(parsebgp_bgp_route_refresh_t *msg)
{
  msg->data_len = 0;
}

void parsebgp_bgp_route_refresh_dump(parsebgp_bgp_route_refresh_t *msg,
                                     int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_route_refresh_t, depth);

  PARSEBGP_DUMP_INT(depth, "AFI", msg->afi);
  PARSEBGP_DUMP_INT(depth, "Subtype", msg->subtype);
  PARSEBGP_DUMP_INT(depth, "SAFI", msg->safi);
  PARSEBGP_DUMP_INT(depth, "Data Length", msg->data_len);
  PARSEBGP_DUMP_DATA(depth, "Data", msg->data, msg->data_len);
}
