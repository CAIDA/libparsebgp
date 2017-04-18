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

#include "bgp_common.h"

#include <list>
#include "../include/parseBMP.h"
#include "../include/AddPathDataContainer.h"

namespace bgp_msg {

/**
 * \class   OpenMsg
 *
 * \brief   BGP open message parser
 * \details This class parses a BGP open message.  It can be extended to create messages.
 *          message.
 */
//class OpenMsg {
//public:
   /**
     * Defines the BGP capabilities
     *      http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
     */
    enum BGP_CAP_CODES {
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
    enum BGP_CAP_ADD_PATH_SEND_RECEIVE_CODES {
            BGP_CAP_ADD_PATH_RECEIVE=1,
            BGP_CAP_ADD_PATH_SEND=2,
            BGP_CAP_ADD_PATH_SEND_RECEIVE=3
    };

    /**
     * defines the Capability BGP header per RFC5492
     *      http://www.iana.org/assignments/capability-codes/capability-codes.xhtml
     */
     struct cap_param {
         u_char       code;                     ///< unambiguously identifies individual capabilities
         u_char       len;                      ///< Capability value length in octets
     } __attribute__ ((__packed__));

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

    /**
     * defines the OPEN BGP header per RFC4271
     */
    struct open_param {
        u_char       type;                     ///< unambiguously identifies parameters (using RFC5492)
                                                 /*
                                                  * Type value of 2 is optional
                                                  */
        u_char       len;                      ///< parameter value length in octets
    } __attribute__ ((__packed__));

    /**
     * BGP open header
     */
    struct open_bgp_hdr {
        u_char            ver;                 ///< Version, currently 4
        uint16_t          asn;                 ///< 2 byte ASN - AS_TRANS = 23456 to indicate 4-octet ASN
        uint16_t          hold;                ///< 2 byte hold time - can be zero or >= 3 seconds
        uint32_t          bgp_id;              ///< 4 byte bgp id of sender - router_id
        u_char            param_len;           ///< optional parameter length - 0 means no params
    } __attribute__((__packed__));

    /**
     * BGP capability header (draft-ietf-idr-dynamic-cap-14)
     */
    struct cap_bgp_hdr {
        u_char      init_ack : 1;              ///< Revision is being init (0) or ack (1)
        u_char      ack_req  : 1;              ///< request for ack
        u_char      resvered : 5;              ///< unused
        u_char      action   : 1;              ///< 0 for advertising and 1 for removing
        uint32_t    seq_num;                   ///< match ack to revision
        u_char      cap;                       ///< Capability code
        uint16_t    cap_len;                   ///< Capability length (2 bytes intead of one)
    } __attribute__((__packed__));


    struct libParseBGP_open_msg_data{
        std::string             peer_addr;      ///< Printed form of the peer address for logging
        bmp_message::peer_info    *peer_info;     ///< Persistent Peer info pointer
    };
     /**
      * Constructor for class
      *
      * \details Handles bgp open messages
      *
      * \param [in]     peerAddr        Printed form of peer address used for logging
      * \param [in]     peer_info       Persistent peer information
      * \param [in]     enable_debug    Debug true to enable, false to disable
      */
     void libParseBGP_open_msg_init(libParseBGP_open_msg_data *open_msg_data, std::string peerAddr, bmp_message::peer_info *peer_info);
//    virtual ~OpenMsg();

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
    size_t libParseBGP_open_msg_parse_open_msg(libParseBGP_open_msg_data *open_msg_data, u_char *data, size_t size, bool openMessageIsSent, uint32_t &asn, uint16_t &holdTime,
                        std::string &bgp_id, std::list<std::string> &capabilities);


//private:
    //bool                    debug;          ///< debug flag to indicate debugging

    /**
     * Parses capabilities from buffer
     *
     * \details
     *      Reads the capabilities from buffer.  The parsed data will be
     *      returned via the out params.
     *
     * \param [in]   data               Pointer to raw bgp payload data, starting at the open/cap message
     * \param [in]   size               Size of the data available to read; prevent overrun when reading
     * \param [in]   openMessageIsSent  If open message is sent. False if received
     * \param [out]  asn                Reference to the ASN that was discovered
     * \param [out]  capabilities       Reference to the capabilities list<string> (decoded values)
     *
     * \return ZERO is error, otherwise a positive value indicating the number of bytes read
     */
    size_t libParseBGP_open_msg_parse_capabilities(libParseBGP_open_msg_data *open_msg_data, u_char *data, size_t size, bool openMessageIsSent, uint32_t &asn,
                             std::list<std::string> &capabilities);
//};

} /* namespace bgp */

#endif /* OPENMSG_H_ */
