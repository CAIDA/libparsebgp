#include "parsebgp_bgp_notification.h"
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
parsebgp_bgp_notification_decode(parsebgp_bgp_opts_t opts,
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
    return INCOMPLETE_MSG;
  }
  if ((msg->data = malloc(msg->data_len)) == NULL) {
    return MALLOC_FAILURE;
  }
  memcpy(msg->data, buf, msg->data_len);
  nread += msg->data_len;

  fprintf(stderr, "DEBUG: NOTIFICATION: Code: %d, Subcode: %d, Data Len: %d\n",
          msg->code, msg->subcode, msg->data_len);

  *lenp = nread;
  return OK;
}

void parsebgp_bgp_notification_destroy(parsebgp_bgp_notification_t *msg)
{
  if (msg == NULL) {
    return;
  }

  free(msg->data);
}
