#include "parsebgp.h"
#include "parsebgp_bgp.h"
#include "parsebgp_bmp.h"
#include "parsebgp_mrt.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>

parsebgp_error_t parsebgp_decode(parsebgp_opts_t opts, parsebgp_msg_type_t type,
                                 parsebgp_msg_t *msg, uint8_t *buffer,
                                 size_t *len)
{
  msg->type = type;

  switch (type) {
  case PARSEBGP_MSG_TYPE_BMP:
    return parsebgp_bmp_decode(&msg->types.bmp, buffer, len);
    break;

  case PARSEBGP_MSG_TYPE_MRT:
    return parsebgp_mrt_decode(&msg->types.mrt, buffer, len);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    return parsebgp_bgp_decode(opts.bgp, &msg->types.bgp, buffer, len);
    break;

  default:
    return PARSEBGP_INVALID_MSG;
  }
  assert(0);
}

parsebgp_msg_t *parsebgp_create_msg()
{
  parsebgp_msg_t *msg = NULL;

  if ((msg = malloc_zero(sizeof(parsebgp_msg_t))) == NULL) {
    return NULL;
  }

  fprintf(stderr,
          "DEBUG: size of parsebgp_msg_t (excluding dynamic memory): %d\n",
          (int)sizeof(parsebgp_msg_t));

  // TODO: other init for the msg here

  return msg;
}

void parsebgp_destroy_msg(parsebgp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  switch (msg->type) {
  case PARSEBGP_MSG_TYPE_MRT:
    parsebgp_mrt_destroy_msg(&msg->types.mrt);
    break;

  case PARSEBGP_MSG_TYPE_BMP:
    parsebgp_bmp_destroy_msg(&msg->types.bmp);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    parsebgp_bgp_destroy_msg(&msg->types.bgp);
    break;

  default:
    // invalid message, give up
    break;
  }

  free(msg);
}
