//
// Created by ojas on 4/21/17.
//

#ifndef PARSE_LIB_LIB_PARSE_COMMON_H_H
#define PARSE_LIB_LIB_PARSE_COMMON_H_H
#include "parse_bmpv1.h"
#include "parse_bgp.h"
#include "parse_mrt.h"

/////////////////////////////////////////////////////////////////
/////////////////////////PARSE BGP STRUCTURE/////////////////////
/////////////////////////////////////////////////////////////////

typedef struct lib_parse_bgp_parsed_bgp{
    common_bgp_hdr common_hdr;

}lib_parse_bgp_parsed_bgp;



/////////////////////////////////////////////////////////////////
/////////////////////////PARSE MRT STRUCTURE/////////////////////
/////////////////////////////////////////////////////////////////

typedef struct lib_parse_bgp_parsed_mrt{

}lib_parse_bgp_parsed_mrt;

union lib_parse_msg{
    lib_parse_bgp_parsed_bgp parsed_bgp_msg;
    lib_parse_bgp_parsed_bmp parsed_bmp_msg;
    lib_parse_bgp_parsed_mrt parsed_mrt_msg;
}lib_parse_msg;



#endif //PARSE_LIB_LIB_PARSE_COMMON_H_H
