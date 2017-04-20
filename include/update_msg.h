/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef UPDATEMSG_H_
#define UPDATEMSG_H_

#include "bgp_common.h"
#include "add_path_data_container.h"
#include "parse_bmp.h"
#include <string>
#include <list>
#include <array>
#include <map>


namespace bgp_msg {
    /**
     * Update header - defined in RFC4271
     */
    struct update_bgp_hdr {
        /**
         * indicates the total len of withdrawn routes field in octets.
         */
        uint16_t withdrawn_len;

        /**
         * Withdrawn routes data pointer
         */
        u_char *withdrawn_ptr;

        /**
         * Total length of the path attributes field in octets
         *
         * A value of 0 indicates NLRI nor path attrs are present
         */
        uint16_t attr_len;

        /**
         * Attribute data pointer
         */
        u_char *attr_ptr;

        /**
         * NLRI data pointer
         */
        u_char *nlri_ptr;
    };
    typedef std::map<uint16_t, std::array<uint8_t, 255>> parsed_ls_attrs_map;

    struct libParseBGP_update_msg_data {
        /**
         * parsed path attributes map
         */
//        std::map<update_attr_types, std::string> parsed_attrs;

        bool debug;                           ///< debug flag to indicate debugging
        //Logger                  *logger;                         ///< Logging class pointer
        std::string peer_addr;                       ///< Printed form of the peer address for logging
        std::string router_addr;                     ///< Router IP address - used for logging
        bool four_octet_asn;                  ///< Indicates true if 4 octets or false if 2
        peer_info *peer_inf;                      ///< Persistent Peer info pointer
    };

    void libParseBGP_update_msg_init(libParseBGP_update_msg_data *update_msg, std::string peer_addr,
                                               std::string router_addr, peer_info *peer_info);

     /**
      * Parses the update message
      *
      * \details
      *      Reads the update message from socket and parses it.  The parsed output will
      *      be added to the DB.
      *
      * \param [in]   data           Pointer to raw bgp payload data, starting at the notification message
      * \param [in]   size           Size of the data available to read; prevent overrun when reading
      * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
      *
      * \return ZERO is error, otherwise a positive value indicating the number of bytes read from update message
      */
     size_t libParseBGP_update_msg_parse_update_msg(libParseBGP_update_msg_data *update_msg, u_char *data, size_t size,
                                                    parsed_update_data &parsed_data, bool &has_end_of_rib_marker);

    /**
     * Parses the BGP attributes in the update
     *
     * \details
     *     Parses all attributes.  Decoded values are updated in 'parsed_data'
     *
     * \param [in]   data       Pointer to the start of the prefixes to be parsed
     * \param [in]   len        Length of the data in bytes to be read
     * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
     */
    void libParseBGP_update_msg_parse_attributes(libParseBGP_update_msg_data *update_msg, u_char *data, uint16_t len, parsed_update_data &parsed_data,
                         bool &has_end_of_rib_marker);

} /* namespace bgp_msg */

#endif /* UPDATEMSG_H_ */
