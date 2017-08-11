#include "parsebgp.h"
#include "parsebgp_utils.h"
#include <assert.h>

parsebgp_error_t parsebgp_decode_msg(parsebgp_msg_type_t type, parsebgp_msg_t *msg,
                            uint8_t *buffer, size_t *len)
{
  msg->type = type;

  // TODO: fixme when other APIs are fixed
  ssize_t nbytes = 0;

  switch (type) {
  case PARSEBGP_MSG_TYPE_MRT:
    nbytes = libparsebgp_parse_mrt_parse_msg(&msg->types.mrt, buffer, *len);
    break;

  case PARSEBGP_MSG_TYPE_BMP:
    nbytes = libparsebgp_parse_bmp_parse_msg(&msg->types.bmp, buffer, *len);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    nbytes = libparsebgp_parse_bgp_parse_msg(&msg->types.bgp, buffer, *len, 1);
    break;

  default:
    return INVALID_MSG;
  }

  if (nbytes < 0) {
    // no need to update remaining
    return nbytes; // contains error code
  }

  // update remaining (len could be 0)
  assert(nbytes < *len);
  *len = nbytes;

  return OK;
}

parsebgp_msg_t *parsebgp_msg_create()
{
  parsebgp_msg_t *msg = NULL;

  if ((msg = malloc_zero(sizeof(parsebgp_msg_t))) == NULL) {
    return NULL;
  }

  // TODO: other init for the msg here

  return msg;
}

void parsebgp_msg_destroy(parsebgp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  switch (msg->type) {
  case PARSEBGP_MSG_TYPE_MRT:
    libparsebgp_parse_mrt_destructor(&msg->types.mrt);
    break;

  case PARSEBGP_MSG_TYPE_BMP:
    libparsebgp_parse_bmp_destructor(&msg->types.bmp);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    libparsebgp_parse_bgp_destructor(&msg->types.bgp);
    break;

  default:
    // invalid message, give up
    break;
  }

  free(msg);
}
