cmake_minimum_required(VERSION 3.2)
project(parse_lib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        src/bgp/MPLinkState.cpp
        src/bgp/MPLinkStateAttr.cpp
        src/bgp/AddPathDataContainer.cpp
        src/bgp/EVPN.cpp
        src/bgp/ExtCommunity.cpp
        src/bgp/MPReachAttr.cpp
        src/bgp/MPUnReachAttr.cpp
        src/bgp/NotificationMsg.cpp
        src/bgp/OpenMsg.cpp
        src/bgp/parseBGP.cpp
        src/bgp/UpdateMsg.cpp
        src/bgp/parseBMP.cpp
        src/include/MPLinkStateAttr.h
        src/include/MPLinkState.h
        src/include/AddPathDataContainer.h
        src/include/bgp_common.h
        src/include/EVPN.h
        src/include/ExtCommunity.h
        src/include/MPReachAttr.h
        src/include/MPUnReachAttr.h
        src/include/NotificationMsg.h
        src/include/OpenMsg.h
        src/include/parseBGP.h
        src/include/UpdateMsg.h
        src/include/parseBMP.h)

add_executable(parse_lib ${SOURCE_FILES})
