//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_LIB_PARSE_COMMON_H_H
#define PARSE_LIB_LIB_PARSE_COMMON_H_H
#include "parse_bmpv1.h"
#include "parse_mrt.h"
#include "parse_bgp.h"


/////////////////////////////////////////////////////////////////
/////////////////////////PARSE MRT STRUCTURE/////////////////////
/////////////////////////////////////////////////////////////////

typedef struct libparsebgp_parsed_mrt{

}libparsebgp_parsed_mrt;

union libparsebgp_parse_msg{
    libparsebgp_parse_bgp_parsed_data parsed_bgp_msg;
    libparsebgp_parse_bmp_parsed_data parsed_bmp_msg;
    libparsebgp_parse_mrt_parsed_data parsed_mrt_msg;
}libparsebgp_parse_msg;

libparsebgp_parse_msg libparsebgp_parse_msg_common_wrapper(u_char* buffer, int& buf_len, int type) {
    libparsebgp_parse_msg parsed_msg;
    switch (type) {
        case MRT_MESSAGE_TYPE: {
            libparsebgp_parse_mrt_parse_msg(buffer, buf_len, &parsed_msg.parsed_mrt_msg);
            break;
        }
        case BMP_MESSAGE_TYPE: {
            libparsebgp_parse_bmp_parse_msg(&parsed_msg.parsed_bmp_msg, buffer, buf_len);
            break;
        }
        case BGP_MESSAGE_TYPE: {
            break;
        }
        default: {
            throw "Type unknown";
        }
    }
    return parsed_msg;
}

#endif //PARSE_LIB_LIB_PARSE_COMMON_H_H
