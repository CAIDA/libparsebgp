/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OPENBMP_ADDPATHDATACONTAINER_H
#define OPENBMP_ADDPATHDATACONTAINER_H

#include "bgp_common.h"
//#include <map>

struct send_receive_codes_for_sent_and_received_open_message_structure {
    int     send_receive_code_for_sent_open_message;
    int     send_receive_code_for_received_open_message;
};

// Peer related data container. First key is afi safi unique key. Second is structure with Add Path information
//typedef std::map<std::string, send_receive_codes_for_sent_and_received_open_message_structure> libparsebgp_addpath_map;

/**
 * Generates unique string from AFI and SAFI combination
 *
 * @param [in] afi              Afi code from RFC
 * @param [in] safi             Safi code form RFC
 *
 * @return string unique for AFI and SAFI combination
 */
//std::string libparsebgp_addpath_get_afi_safi_key_string(int afi, int safi);

/**
 * Add Add Path data to persistent storage
 *
 * @param [in] afi              Afi code from RFC
 * @param [in] safi             Safi code form RFC
 * @param [in] send_receive     Send Recieve code from RFC
 * @param [in] sent_open        Is obtained from sent open message. False if from recieved
 */
//void libparsebgp_addpath_add(libparsebgp_addpath_map &addpath_map, int afi, int safi, int send_receive, bool sent_open);

/**
 * Is add path capability enabled for such AFI and SAFI
 *
 * @param [in] afi              Afi code from RFC
 * @param [in] safi             Safi code form RFC
 *
 * @return is enabled
 */
//bool libparsebgp_addpath_is_enabled(libparsebgp_addpath_map &addpath_map, int afi, int safi);

#endif //OPENBMP_ADDPATHDATACONTAINER_