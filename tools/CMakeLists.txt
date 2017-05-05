cmake_minimum_required(VERSION 2.8.9)
set(CMAKE_CXX_STANDARD 11)
project (bmp_tool C CXX)

#Bring the headers, such as Student.h into the project
include_directories(../include)

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "../src/*.cpp")
 
#Generate the static library from the sources
add_library(parse SHARED ${SOURCES})
 
#Set the location for library installation -- i.e., /usr/lib in this case
# not really necessary in this example. Use "sudo make install" to apply
install(TARGETS parse DESTINATION parselib_shared/)

add_executable(libtest lib_parse_bgp_tool.cpp)
target_link_libraries(libtest parse)
