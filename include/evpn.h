#ifndef _OPENBMP_EVPN_H_
#define _OPENBMP_EVPN_H_

#include <cstdint>
#include <cinttypes>
#include <sys/types.h>
#include <iomanip>
#include <arpa/inet.h>
#include "update_msg.h"

enum evpn_routes_types {
    EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY = 1,
    EVPN_ROUTE_TYPE_MAC_IP_ADVERTISMENT,
    EVPN_ROUTE_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG,
    EVPN_ROUTE_TYPE_ETHERNET_SEGMENT_ROUTE,
};

/**
 * Parse Route Distinguisher
 *
 * @details
 *      Will parse the Route Distinguisher. Based on https://tools.ietf.org/html/rfc4364#section-4.2
 *
 * @param [in/out]  data_pointer  Pointer to the beginning of Route Distinguisher
 * @param [out]     rd_type                    Reference to RD type.
 * @param [out]     rd_assigned_number         Reference to Assigned Number subfield
 * @param [out]     rd_administrator_subfield  Reference to Administrator subfield
 */
void libparsebgp_evpn_parse_route_distinguisher(u_char *data_pointer, uint8_t *rd_type, std::string *rd_assigned_number,
                                                std::string *rd_administrator_subfield);

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
 */
ssize_t libparsebgp_evpn_parse_nlri_data(update_path_attrs *path_attrs,u_char *data, uint16_t data_len, bool is_unreach);

#endif //_OPENBMP_EVPN_H_
