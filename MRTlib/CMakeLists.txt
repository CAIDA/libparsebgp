cmake_minimum_required(VERSION 3.6)
project(MRTlib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        bgp/parseMRT.cpp
        include/parseMRT.h)

add_executable(MRTlib ${SOURCE_FILES})