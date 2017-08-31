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
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.bmp);
    return parsebgp_bmp_decode(&opts, msg->types.bmp, buffer, len);
    break;

  case PARSEBGP_MSG_TYPE_MRT:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.mrt);
    return parsebgp_mrt_decode(&opts, msg->types.mrt, buffer, len);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    PARSEBGP_MAYBE_MALLOC_ZERO(msg->types.bgp);
    return parsebgp_bgp_decode(&opts, msg->types.bgp, buffer, len);
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

  return msg;
}

void parsebgp_clear_msg(parsebgp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  switch (msg->type) {
  case PARSEBGP_MSG_TYPE_MRT:
    parsebgp_mrt_clear_msg(msg->types.mrt);
    break;

  case PARSEBGP_MSG_TYPE_BMP:
    parsebgp_bmp_clear_msg(msg->types.bmp);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    parsebgp_bgp_clear_msg(msg->types.bgp);
    break;

  default:
    // invalid message, give up
    break;
  }
}

void parsebgp_destroy_msg(parsebgp_msg_t *msg)
{
  if (msg == NULL) {
    return;
  }

  parsebgp_mrt_destroy_msg(msg->types.mrt);
  parsebgp_bmp_destroy_msg(msg->types.bmp);
  parsebgp_bgp_destroy_msg(msg->types.bgp);

  free(msg);
}

void parsebgp_dump_msg(parsebgp_msg_t *msg)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_msg_t, 0);
  PARSEBGP_DUMP_INT(0, "Type", msg->type);

  switch (msg->type) {
  case PARSEBGP_MSG_TYPE_MRT:
    parsebgp_mrt_dump_msg(msg->types.mrt, 1);
    break;

  case PARSEBGP_MSG_TYPE_BMP:
    parsebgp_bmp_dump_msg(msg->types.bmp, 1);
    break;

  case PARSEBGP_MSG_TYPE_BGP:
    parsebgp_bgp_dump_msg(msg->types.bgp, 1);
    break;

  default:
    PARSEBGP_DUMP_INFO(0, "UNKNOWN MESSAGE TYPE\n");
    break;
  }

  printf("\n");
}
