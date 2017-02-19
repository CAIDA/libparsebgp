cmake_minimum_required(VERSION 3.6)
project(parse_lib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        src/bgp/linkstate/MPLinkState.cpp
        src/bgp/linkstate/MPLinkState.h
        src/bgp/linkstate/MPLinkStateAttr.cpp
        src/bgp/linkstate/MPLinkStateAttr.h
        src/bgp/AddPathDataContainer.cpp
        src/bgp/EVPN.cpp
        src/bgp/ExtCommunity.cpp
        src/bgp/MPReachAttr.cpp
        src/bgp/MPUnReachAttr.cpp
        src/bgp/NotificationMsg.cpp
        src/bgp/OpenMsg.cpp
        src/bgp/parseBGP.cpp
        src/bgp/UpdateMsg.cpp
        src/include/bgp/AddPathDataContainer.h
        src/include/bgp/bgp_common.h
        src/include/bgp/EVPN.h
        src/include/bgp/ExtCommunity.h
        src/include/bgp/MPReachAttr.h
        src/include/bgp/MPUnReachAttr.h
        src/include/bgp/NotificationMsg.h
        src/include/bgp/OpenMsg.h
        src/include/bgp/parseBGP.h
        src/include/bgp/UpdateMsg.h
        src/include/parseBMP.h
        src/parseBMP.cpp)

add_executable(parse_lib ${SOURCE_FILES})