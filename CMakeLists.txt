cmake_minimum_required(VERSION 3.2)
project(parse_lib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        src/MPLinkState.cpp
        src/MPLinkStateAttr.cpp
        src/AddPathDataContainer.cpp
        src/EVPN.cpp
        src/ExtCommunity.cpp
        src/MPReachAttr.cpp
        src/MPUnReachAttr.cpp
        src/NotificationMsg.cpp
        src/OpenMsg.cpp
        src/parseBGP.cpp
        src/UpdateMsg.cpp
        src/parseBMP.cpp
        src/parseUtils.cpp
        src/parseMRT.cpp
        include/MPLinkStateAttr.h
        include/MPLinkState.h
        include/AddPathDataContainer.h
        include/bgp_common.h
        include/EVPN.h
        include/ExtCommunity.h
        include/MPReachAttr.h
        include/MPUnReachAttr.h
        include/NotificationMsg.h
        include/OpenMsg.h
        include/parseBGP.h
        include/UpdateMsg.h
        include/parseBMP.h
        include/parseUtils.h
        include/parseMRT.h)

add_executable(parse_lib ${SOURCE_FILES})
