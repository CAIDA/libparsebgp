//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_LIB_PARSE_COMMON_H_H
#define PARSE_LIB_LIB_PARSE_COMMON_H_H
#include "parse_bmp.h"
#include "parse_mrt.h"
#include "parse_bgp.h"

/**
 * Message types supported by libparsebgp
 */
enum libparsebgp_parse_msg_types {MRT_MESSAGE_TYPE = 1, BMP_MESSAGE_TYPE, BGP_MESSAGE_TYPE};

/**
 * OBJECT: libparsebgp_parse_msg
 *
 * Parse Message schema
 */
struct libparsebgp_parse_msg{
    libparsebgp_parse_bgp_parsed_data parsed_bgp_msg;
    libparsebgp_parsed_bmp_parsed_data parsed_bmp_msg;
    libparsebgp_parse_mrt_parsed_data parsed_mrt_msg;
};

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
ssize_t libparsebgp_parse_msg_common_wrapper(libparsebgp_parse_msg &parsed_msg, u_char* buffer, int buf_len, int type) {
    ssize_t read_size = 0;
    switch (type) {
        case MRT_MESSAGE_TYPE: {
            read_size=libparsebgp_parse_mrt_parse_msg(&parsed_msg.parsed_mrt_msg, buffer, buf_len);
            break;
        }
        case BMP_MESSAGE_TYPE: {
            read_size=libparsebgp_parse_bmp_parse_msg(&parsed_msg.parsed_bmp_msg, buffer, buf_len);
            break;
        }
        case BGP_MESSAGE_TYPE: {
            read_size=libparsebgp_parse_bgp_parse_msg(parsed_msg.parsed_bgp_msg, buffer, buf_len);
            break;
        }
        default: {
            return INVALID_MSG; //throw "Type unknown";
        }
    }
    return read_size;
}

#endif //PARSE_LIB_LIB_PARSE_COMMON_H_H