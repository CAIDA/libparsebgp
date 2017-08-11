//
// Created by ojas on 4/21/17.
//

#ifndef __PARSEBGP_H
#define __PARSEBGP_H

#include "parsebgp_bgp.h"
#include "parsebgp_bmp.h"
#include "parsebgp_mrt.h"
#include <inttypes.h>
#include <unistd.h>

/**
 * Message types supported by libparsebgp
 */
enum libparsebgp_parse_msg_types {
  MRT_MESSAGE_TYPE = 1,
  BMP_MESSAGE_TYPE,
  BGP_MESSAGE_TYPE
};

enum parse_msg_error {
  INCOMPLETE_MSG = -1, ///< Buffer does not contain the entire message
  LARGER_MSG_LEN =
    -2, ///< Message length is larger than the maximum possible message length
  CORRUPT_MSG = -3, ///< Message does not follow the formats specified in RFCs
  ERR_READING_MSG = -4, ///< Error in reading from buffer
  INVALID_MSG = -5, ///< Part of message is different from the expected values
  NOT_YET_IMPLEMENTED = -6 ///< A feature not yet implemented
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
 * @return number of bytes read if successful, 0 if a partial message was
 * encountered, or < 0 if an error occurred
 *
 * TODO: better return codes, consider passing read length as parameter
 */
ssize_t libparsebgp_parse_msg_common_wrapper(libparsebgp_parse_msg *parsed_msg,
                                             uint8_t **buffer, int buf_len,
                                             int type);

/**
 * A common destructor function for the parsed message
 * @param parsed_msg struct storing the parsed data
 */
void libparsebgp_parse_msg_common_destructor(libparsebgp_parse_msg *parsed_msg);

#endif // __PARSEBGP_H
