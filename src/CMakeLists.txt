cmake_minimum_required(VERSION 2.8.12.2)
project(parsebgp)
set(CMAKE_BUILD_TYPE Release)

include_directories(include)

#set(SOURCES libcode.cpp)
file(GLOB SOURCES "*/*.cpp")

add_library(parser SHARED ${SOURCES})
install(TARGETS parser DESTINATION /usr/lib)

