cmake_minimum_required(VERSION 3.2)
project(parse_lib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        include/lib_parse_common.h
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
        include/parse_bmp.h
        src/mp_link_state.c
        src/mp_link_state_attr.c
        src/add_path_data_container.c
        src/evpn.c
        src/ext_community.c
        src/mp_reach_attr.c
        src/mp_un_reach_attr.c
        src/notification_msg.c
        src/open_msg.c
        src/parse_bgp.c
        src/parse_bmp.c
        src/update_msg.c
        src/parse_utils.c
        src/parse_mrt.c
        )

add_executable(parse_lib ${SOURCE_FILES})
