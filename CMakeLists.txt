cmake_minimum_required(VERSION 3.6)
project(parse_lib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        src/bgp/linkstate/MPLinkState.cpp
        
        src/bgp/linkstate/MPLinkStateAttr.cpp
        src/bgp/AddPathDataContainer.cpp
        src/bgp/EVPN.cpp
        src/bgp/ExtCommunity.cpp
        src/bgp/MPReachAttr.cpp
        src/bgp/MPUnReachAttr.cpp
        src/bgp/NotificationMsg.cpp
        src/bgp/OpenMsg.cpp
        src/bgp/parseBGP.cpp
        src/bgp/UpdateMsg.cpp
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
        src/include/parseBMP.h
        src/parseBMP.cpp)

add_executable(parse_lib ${SOURCE_FILES})
