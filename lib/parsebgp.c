#include "parsebgp.h"

ssize_t libparsebgp_parse_msg_common_wrapper(libparsebgp_parse_msg *parsed_msg,
                                             uint8_t **buffer, int buf_len,
                                             int type)
{
  ssize_t read_size = 0;
  parsed_msg->msg_type = type;
  switch (type) {
  case MRT_MESSAGE_TYPE: {
    read_size = libparsebgp_parse_mrt_parse_msg(
      &parsed_msg->libparsebgp_parse_msg_parsed.parsed_mrt_msg, *buffer,
      buf_len);
    break;
  }
  case BMP_MESSAGE_TYPE: {
    read_size = libparsebgp_parse_bmp_parse_msg(
      &parsed_msg->libparsebgp_parse_msg_parsed.parsed_bmp_msg, *buffer,
      buf_len);
    break;
  }
  case BGP_MESSAGE_TYPE: {
    read_size = libparsebgp_parse_bgp_parse_msg(
      &parsed_msg->libparsebgp_parse_msg_parsed.parsed_bgp_msg, *buffer,
      buf_len, 1);
    break;
  }
  default: {
    return INVALID_MSG;
  }
  }
  return read_size;
}

void libparsebgp_parse_msg_common_destructor(libparsebgp_parse_msg *parsed_msg)
{
  switch (parsed_msg->msg_type) {
  case MRT_MESSAGE_TYPE: {
    libparsebgp_parse_mrt_destructor(
      &parsed_msg->libparsebgp_parse_msg_parsed.parsed_mrt_msg);
    break;
  }
  case BMP_MESSAGE_TYPE: {
    libparsebgp_parse_bmp_destructor(
      &parsed_msg->libparsebgp_parse_msg_parsed.parsed_bmp_msg);
    break;
  }
  case BGP_MESSAGE_TYPE: {
    libparsebgp_parse_bgp_destructor(
      &parsed_msg->libparsebgp_parse_msg_parsed.parsed_bgp_msg);
    break;
  }
  }
}
