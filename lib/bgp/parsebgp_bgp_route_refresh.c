#include "parsebgp_bgp_route_refresh.h"
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

parsebgp_error_t
parsebgp_bgp_route_refresh_decode(parsebgp_bgp_opts_t opts,
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
    return INCOMPLETE_MSG;
  }
  if ((msg->data = malloc(msg->data_len)) == NULL) {
    return MALLOC_FAILURE;
  }
  memcpy(msg->data, buf, msg->data_len);
  nread += msg->data_len;

  fprintf(
    stderr,
    "DEBUG: ROUTE-REFRESH: AFI: %d, Subtype: %d, SAFI: %d, Data Len: %d\n",
    msg->afi, msg->subtype, msg->safi, msg->data_len);

  *lenp = nread;
  return OK;
}

void parsebgp_bgp_route_refresh_destroy(parsebgp_bgp_route_refresh_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->data);
}
