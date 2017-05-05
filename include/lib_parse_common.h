//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_LIB_PARSE_COMMON_H_H
#define PARSE_LIB_LIB_PARSE_COMMON_H_H
#include "parse_bmpv1.h"
#include "parse_mrt.h"
#include "parse_bgp.h"

enum libparsebgp_parse_msg_types {MRT_MESSAGE_TYPE = 1, BMP_MESSAGE_TYPE, BGP_MESSAGE_TYPE};


struct libparsebgp_parse_msg{
    uint32_t read_size;
    libparsebgp_parse_bgp_parsed_data parsed_bgp_msg;
    libparsebgp_parsed_bmp_parsed_data parsed_bmp_msg;
    libparsebgp_parse_mrt_parsed_data parsed_mrt_msg;
};

libparsebgp_parse_msg libparsebgp_parse_msg_common_wrapper(u_char* buffer, uint32_t buf_len, int type) {
    libparsebgp_parse_msg parsed_msg;
    switch (type) {
        case MRT_MESSAGE_TYPE: {
            parsed_msg.read_size=libparsebgp_parse_mrt_parse_msg(&parsed_msg.parsed_mrt_msg, buffer, buf_len);
            break;
        }
        case BMP_MESSAGE_TYPE: {
            parsed_msg.read_size=libparsebgp_parse_bmp_parse_msg(&parsed_msg.parsed_bmp_msg, buffer, buf_len);
            break;
        }
        case BGP_MESSAGE_TYPE: {
            parsed_msg.read_size=libparsebgp_parse_bgp_parse_msg(&parsed_msg.parsed_bgp_msg, buffer, buf_len);
            break;
        }
        default: {
            throw "Type unknown";
        }
    }
    return parsed_msg;
}

#endif //PARSE_LIB_LIB_PARSE_COMMON_H_H
