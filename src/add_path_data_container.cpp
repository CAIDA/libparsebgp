/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/add_path_data_container.h"
#include "../include/open_msg.h"


/**
 * Add Add Path data to persistent storage
 *
 * \param [in] afi              Afi code from RFC
 * \param [in] safi             Safi code form RFC
 * \param [in] send_receive     Send Recieve code from RFC
 * \param [in] sent_open        Is obtained from sent open message. False if from recieved
 */
void libparsebgp_addpath_add(libparsebgp_addpath_map &addpath_map, int afi, int safi, int send_receive, bool sent_open) {
    //AddPathMap::iterator iterator = this->addPathMap.find(this->getAFiSafiKeyString(afi, safi));
    libparsebgp_addpath_map::iterator iterator = addpath_map.find(libparsebgp_addpath_get_afi_safi_key_string(afi, safi));
    if(iterator == addpath_map.end()) {
        send_receive_codes_for_sent_and_received_open_message_structure new_structure;

        if (sent_open) {
            new_structure.send_receive_code_for_sent_open_message = send_receive;
        } else {
            new_structure.send_receive_code_for_received_open_message = send_receive;
        }

        addpath_map.insert(std::pair<std::string, send_receive_codes_for_sent_and_received_open_message_structure>(
                libparsebgp_addpath_get_afi_safi_key_string(afi, safi),
                new_structure
        ));
    } else {
        if (sent_open) {
            iterator->second.send_receive_code_for_sent_open_message = send_receive;
        } else {
            iterator->second.send_receive_code_for_received_open_message = send_receive;
        }
    }
}

/**
 * Generates unique string from AFI and SAFI combination
 *
 * \param [in] afi              Afi code from RFC
 * \param [in] safi             Safi code form RFC
 *
 * \return string unique for AFI and SAFI combination
 */
std::string libparsebgp_addpath_get_afi_safi_key_string(int afi, int safi) {
    std::string result = std::to_string(static_cast<long long>(afi));
    result.append("_");
    result.append(std::to_string(static_cast<long long>(safi)));
    return result;
}

/**
 * Is add path capability enabled for such AFI and SAFI
 *
 * \param [in] afi              Afi code from RFC
 * \param [in] safi             Safi code form RFC
 *
 * \return is enabled
 */
bool libparsebgp_addpath_is_enabled(libparsebgp_addpath_map &addpath_map, int afi, int safi) {
    libparsebgp_addpath_map::iterator iterator = addpath_map.find(libparsebgp_addpath_get_afi_safi_key_string(afi, safi));

    if(iterator == addpath_map.end()) {
        return false;
    } else {
        // Following the rule:
        // add_path_<afi/safi> = true IF (SENT_OPEN has ADD-PATH sent or both) AND (RECV_OPEN has ADD-PATH recv or both)
        return (
            iterator->second.send_receive_code_for_sent_open_message == BGP_CAP_ADD_PATH_RECEIVE or
                    iterator->second.send_receive_code_for_sent_open_message == BGP_CAP_ADD_PATH_SEND_RECEIVE
            ) and (
            iterator->second.send_receive_code_for_received_open_message == BGP_CAP_ADD_PATH_SEND or
                    iterator->second.send_receive_code_for_received_open_message == BGP_CAP_ADD_PATH_SEND_RECEIVE
            );
    }
}
