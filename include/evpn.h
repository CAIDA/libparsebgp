#ifndef _OPENBMP_EVPN_H_
#define _OPENBMP_EVPN_H_

#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "update_msg.h"

enum evpn_routes_types {
    EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY = 1,
    EVPN_ROUTE_TYPE_MAC_IP_ADVERTISMENT,
    EVPN_ROUTE_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG,
    EVPN_ROUTE_TYPE_ETHERNET_SEGMENT_ROUTE,
};

/**
 * Parse all EVPN nlri's
 *
 * @details
 *      Parsing based on https://tools.ietf.org/html/rfc7432.  Will process all NLRI's in data.
 *
 * @param [in]   path_attrs             Structure storing the path attributes
 * @param [in]   data                   Pointer to the start of the prefixes to be parsed
 * @param [in]   data_len               Length of the data in bytes to be read
 * @param [in]   is_unreach             Indicates whether MP_REACH or MP_UNREACH
 *
 * @return number of bytes read
 */
ssize_t libparsebgp_evpn_parse_nlri_data(update_path_attrs *path_attrs,u_char *data, uint16_t data_len, bool is_unreach);

#endif //_OPENBMP_EVPN_H_
