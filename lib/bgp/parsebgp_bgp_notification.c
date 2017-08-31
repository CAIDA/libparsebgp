#include "parsebgp_bgp_notification.h"
#include "parsebgp_error.h"
#include "parsebgp_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

parsebgp_error_t
parsebgp_bgp_notification_decode(parsebgp_opts_t *opts,
                                 parsebgp_bgp_notification_t *msg, uint8_t *buf,
                                 size_t *lenp, size_t remain)
{
  size_t len = *lenp, nread = 0;

  // Error Code
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->code);

  // Error Subcode
  PARSEBGP_DESERIALIZE_VAL(buf, len, nread, msg->subcode);

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

void parsebgp_bgp_notification_destroy(parsebgp_bgp_notification_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->data);

  free(msg);
}

void parsebgp_bgp_notification_clear(parsebgp_bgp_notification_t *msg)
{
  msg->data_len = 0;
}

void parsebgp_bgp_notification_dump(parsebgp_bgp_notification_t *msg, int depth)
{
  PARSEBGP_DUMP_STRUCT_HDR(parsebgp_bgp_notification_t, depth);

  PARSEBGP_DUMP_INT(depth, "Error Code", msg->code);
  PARSEBGP_DUMP_INT(depth, "Error Subcode", msg->subcode);
  PARSEBGP_DUMP_INT(depth, "Data Length", msg->data_len);
  PARSEBGP_DUMP_DATA(depth, "Data", msg->data, msg->data_len);
}
