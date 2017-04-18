/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "../include/AddPathDataContainer.h"
#include "../include/OpenMsg.h"

//AddPathDataContainer::AddPathDataContainer() {
//}

//AddPathDataContainer::~AddPathDataContainer() {
//}

/**
 * Add Add Path data to persistent storage
 *
 * \param [in] afi              Afi code from RFC
 * \param [in] safi             Safi code form RFC
 * \param [in] send_receive     Send Recieve code from RFC
 * \param [in] sent_open        Is obtained from sent open message. False if from recieved
 */
void libParseBGP_addpath_add(libParseBGP_addpath_map &addpath_map, int afi, int safi, int send_receive, bool sent_open) {
    //AddPathMap::iterator iterator = this->addPathMap.find(this->getAFiSafiKeyString(afi, safi));
    libParseBGP_addpath_map::iterator iterator = addpath_map.find(libParseBGP_addpath_get_afi_safi_key_string(afi, safi));
    if(iterator == addpath_map.end()) {
        sendReceiveCodesForSentAndReceivedOpenMessageStructure newStructure;

        if (sent_open) {
            newStructure.sendReceiveCodeForSentOpenMessage = send_receive;
        } else {
            newStructure.sendReceiveCodeForReceivedOpenMessage = send_receive;
        }

        addpath_map.insert(std::pair<std::string, sendReceiveCodesForSentAndReceivedOpenMessageStructure>(
                libParseBGP_addpath_get_afi_safi_key_string(afi, safi),
                newStructure
        ));
    } else {
        if (sent_open) {
            iterator->second.sendReceiveCodeForSentOpenMessage = send_receive;
        } else {
            iterator->second.sendReceiveCodeForReceivedOpenMessage = send_receive;
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
std::string libParseBGP_addpath_get_afi_safi_key_string(int afi, int safi) {
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
bool libParseBGP_addpath_is_enabled(libParseBGP_addpath_map &addpath_map, int afi, int safi) {
    libParseBGP_addpath_map::iterator iterator = addpath_map.find(libParseBGP_addpath_get_afi_safi_key_string(afi, safi));

    if(iterator == addpath_map.end()) {
        return false;
    } else {
        // Following the rule:
        // add_path_<afi/safi> = true IF (SENT_OPEN has ADD-PATH sent or both) AND (RECV_OPEN has ADD-PATH recv or both)
        return (
            iterator->second.sendReceiveCodeForSentOpenMessage == bgp_msg::BGP_CAP_ADD_PATH_RECEIVE or
                    iterator->second.sendReceiveCodeForSentOpenMessage == bgp_msg::BGP_CAP_ADD_PATH_SEND_RECEIVE
            ) and (
            iterator->second.sendReceiveCodeForReceivedOpenMessage == bgp_msg::BGP_CAP_ADD_PATH_SEND or
                    iterator->second.sendReceiveCodeForReceivedOpenMessage == bgp_msg::BGP_CAP_ADD_PATH_SEND_RECEIVE
            );
    }
}
