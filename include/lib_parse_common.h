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



#endif //PARSE_LIB_LIB_PARSE_COMMON_H_H
