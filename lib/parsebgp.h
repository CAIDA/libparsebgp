//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_LIB_PARSE_COMMON_H_H
#define PARSE_LIB_LIB_PARSE_COMMON_H_H

#include "parse_bgp.h"
#include "parse_bmp.h"
#include "parse_mrt.h"
#include "parse_utils.h"

/**
 * Message types supported by libparsebgp
 */
enum libparsebgp_parse_msg_types {
  MRT_MESSAGE_TYPE = 1,
  BMP_MESSAGE_TYPE,
  BGP_MESSAGE_TYPE
};

/**
 * OBJECT: libparsebgp_parse_msg
 *
 * Parse Message schema
 */
typedef struct libparsebgp_parse_msg {
  int msg_type;                        ///< Type of message parsed
  union libparsebgp_parse_msg_parsed { ///< Union of message
    libparsebgp_parse_bgp_parsed_data
      parsed_bgp_msg; ///< struct for BGP message
    libparsebgp_parse_bmp_parsed_data
      parsed_bmp_msg; ///< Struct for BMP message
    libparsebgp_parse_mrt_parsed_data
      parsed_mrt_msg; ///< Struct for MRT message
  } libparsebgp_parse_msg_parsed;
} libparsebgp_parse_msg;

/**
 * Main function which will be called for parsing MRT, BMP or BGP message
 *
 * @param [in] parsed_msg    The union which stores the parsed data
 * @param [in] buffer        Buffer containing the raw message
 * @param [in] buf_len       Size of buffer
 * @param [in] type          Type of message - 1 for MRT, 2 for BMP, 3 for BGP
 *
 * @return number of bytes read
 */
ssize_t libparsebgp_parse_msg_common_wrapper(libparsebgp_parse_msg *parsed_msg,
                                             u_char **buffer, int buf_len,
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
      buf_len, true);
    break;
  }
  default: {
    return INVALID_MSG;
  }
  }
  return read_size;
}

/**
 * A common destructor function for the parsed message
 * @param parsed_msg struct storing the parsed data
 */
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

#endif // PARSE_LIB_LIB_PARSE_COMMON_H_H