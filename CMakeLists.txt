cmake_minimum_required(VERSION 3.2)
project(parse_lib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
#        include/parse_common.h
        include/mp_link_state_attr.h
        include/mp_link_state.h
        include/add_path_data_container.h
        include/bgp_common.h
        include/evpn.h
        include/ext_community.h
        include/mp_reach_attr.h
        include/mp_un_reach_attr.h
        include/notification_msg.h
        include/open_msg.h
        include/parse_bgp.h
        include/update_msg.h
        include/parse_utils.h
        include/parse_mrt.h
        include/parse_bmpv1.h
        include/libParseBGP.h
        src/mp_link_state.cpp
        src/mp_link_state_attr.cpp
        src/add_path_data_container.cpp
        src/evpn.cpp
        src/ext_community.cpp
        src/mp_reach_attr.cpp
        src/mp_un_reach_attr.cpp
        src/notification_msg.cpp
        src/open_msg.cpp
        src/parse_bgp.cpp
        src/parse_bmpv1.cpp
        src/update_msg.cpp
        src/parse_utils.cpp
        src/parse_mrt.cpp
        )

add_executable(parse_lib ${SOURCE_FILES})
