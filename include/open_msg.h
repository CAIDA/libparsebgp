/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OPENMSG_H_
#define OPENMSG_H_

#include <iostream>
#include <list>

//namespace bgp_msg {

/**
 * \class   OpenMsg
 *
 * \brief   BGP open message parser
 * \details This class parses a BGP open message.  It can be extended to create messages.
 *          message.
 */
 /**
     * Defines the BGP capabilities
     *      http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
     */
    enum bgp_cap_codes {
            BGP_CAP_MPBGP=1,
            BGP_CAP_ROUTE_REFRESH,
            BGP_CAP_OUTBOUND_FILTER,
            BGP_CAP_MULTI_ROUTES_DEST,

            BGP_CAP_EXT_NEXTHOP=5,                  // RFC 5549

            BGP_CAP_GRACEFUL_RESTART=64,
            BGP_CAP_4OCTET_ASN,

            BGP_CAP_DYN_CAP=67,
            BGP_CAP_MULTI_SESSION,
            BGP_CAP_ADD_PATH,
            BGP_CAP_ROUTE_REFRESH_ENHANCED,
            BGP_CAP_ROUTE_REFRESH_OLD=128
    };

    /**
     * Defines the Add Path BGP capability's send/recieve code
     *      https://tools.ietf.org/html/rfc7911#section-4
     */
    enum bgp_cap_add_path_send_receive_codes {
            BGP_CAP_ADD_PATH_RECEIVE=1,
            BGP_CAP_ADD_PATH_SEND=2,
            BGP_CAP_ADD_PATH_SEND_RECEIVE=3
    };

    /**
     * Defines the MPBGP capability data
     */
     struct cap_mpbgp_data {
         uint16_t       afi;                    ///< Address family to support
          u_char         reserved;               ///< Unused
          u_char         safi;                   ///< Subsequent address family
      } __attribute__ ((__packed__));

    /**
    * Defines the Add Path capability data
    */
    struct cap_add_path_data {
        uint16_t       afi;
        uint8_t        safi;
        uint8_t        send_recieve;
    } __attribute__ ((__packed__));

    union capability_value {
        uint32_t asn;
        cap_add_path_data add_path_data;
        cap_mpbgp_data mpbgp_data;
    };

    struct open_capabilities {
        uint8_t cap_code;
        uint8_t cap_len;
        capability_value cap_values;
    };

    struct open_param {
        uint8_t param_type;
        uint8_t param_len;
        std::list<open_capabilities> param_values;
    };

    typedef struct libparsebgp_open_msg_data{
        uint8_t           ver;                 ///< Version, currently 4
        uint16_t          asn;                 ///< 2 byte ASN - AS_TRANS = 23456 to indicate 4-octet ASN
        uint16_t          hold_time;           ///< 2 byte hold time - can be zero or >= 3 seconds
        unsigned char     bgp_id[4];           ///< 4 byte bgp id of sender - router_id
        uint8_t           opt_param_len;       ///< optional parameter length - 0 means no params
        std::list<open_param>  opt_param;           ///< optional parameter
    }libparsebgp_open_msg_data;

    /**
     * Parses an open message
     *
     * \details
     *      Reads the open message from buffer.  The parsed data will be
     *      returned via the out params.
     *
     * \param [in]   data         Pointer to raw bgp payload data, starting at the notification message
     * \param [in]   size         Size of the data parsed_msg.error_textfer, to prevent overrun when reading
     * \param [in]   openMessageIsSent  If open message is sent. False if received
     * \param [out]  asn          Reference to the ASN that was discovered
     * \param [out]  holdTime     Reference to the hold time
     * \param [out]  bgp_id       Reference to string for bgp ID in printed form
     * \param [out]  capabilities Reference to the capabilities list<string> (decoded values)
     *
     * \return ZERO is error, otherwise a positive value indicating the number of bytes read for the open message
     */
    int libparsebgp_open_msg_parse_open_msg(libparsebgp_open_msg_data *open_msg_data, u_char *data, size_t size, bool openMessageIsSent);

//} /* namespace bgp */

#endif /* OPENMSG_H_ */
