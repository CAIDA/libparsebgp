#ifndef _OPENBMP_EVPN_H_
#define _OPENBMP_EVPN_H_

#include <cstdint>
#include <cinttypes>
#include <sys/types.h>
#include <iomanip>
#include <arpa/inet.h>
#include "mp_reach_attr.h"
#include "mp_un_reach_attr.h"

//namespace bgp_msg {
enum evpn_routes_types {
    EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY = 1,
    EVPN_ROUTE_TYPE_MAC_IP_ADVERTISMENT,
    EVPN_ROUTE_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG,
    EVPN_ROUTE_TYPE_ETHERNET_SEGMENT_ROUTE,
};


struct libParseBGP_evpn_data {
    std::string peer_addr;                       ///< Printed form of the peer address for logging
    bool is_un_reach;                       ///< True if MP UNREACH, false if MP REACH

    parsed_update_data *parsed_data;       ///< Parsed data structure
};

    /**
     * Constructor for class
     *
     * \details Handles bgp Extended Communities
     *
     * \param [in]     logPtr       Pointer to existing Logger for app logging
     * \param [in]     peerAddr     Printed form of peer address used for logging
     * \param [in]     isUnreach    True if MP UNREACH, false if MP REACH
     * \param [out]    parsed_data  Reference to parsed_update_data; will be updated with all parsed data
     * \param [in]     enable_debug Debug true to enable, false to disable
     */

    void libParseBGP_evpn_init(libParseBGP_evpn_data *evpn_data, std::string peerAddr, bool is_unreach, parsed_update_data *parsed_data);

    /**
     * Parse Route Distinguisher
     *
     * \details
     *      Will parse the Route Distinguisher. Based on https://tools.ietf.org/html/rfc4364#section-4.2
     *
     * \param [in/out]  data_pointer  Pointer to the beginning of Route Distinguisher
     * \param [out]     rd_type                    Reference to RD type.
     * \param [out]     rd_assigned_number         Reference to Assigned Number subfield
     * \param [out]     rd_administrator_subfield  Reference to Administrator subfield
     */
    void libParseBGP_evpn_parse_route_distinguisher(u_char *data_pointer, uint8_t *rd_type, std::string *rd_assigned_number,
                                  std::string *rd_administrator_subfield);

    /**
     * Parse all EVPN nlri's
     *
     * \details
     *      Parsing based on https://tools.ietf.org/html/rfc7432.  Will process all NLRI's in data.
     *
     * \param [in]   data                   Pointer to the start of the prefixes to be parsed
     * \param [in]   data_len               Length of the data in bytes to be read
     *
     */
    void libParseBGP_evpn_parse_nlri_data(libParseBGP_evpn_data *evpn_data,u_char *data, uint16_t data_len);
//}


#endif //_OPENBMP_EVPN_H_
