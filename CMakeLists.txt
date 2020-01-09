# Tested with 3.13, feel free to modify if you tested it with an older version.
cmake_minimum_required(VERSION 3.13)

# Keep these versions in sync with configure.ac
set(LIBPARSEBGP_VERSION   "1.0.0")
set(LIBPARSEBGP_SOVERSION "2.0.0")

project(libparsebgp VERSION ${LIBPARSEBGP_VERSION})

# Convert major.minor.patch to major.mid.minor for exporting.
set(LIBPARSEBGP_MAJOR_VERSION ${PROJECT_VERSION_MAJOR})
set(LIBPARSEBGP_MID_VERSION   ${PROJECT_VERSION_MINOR})
set(LIBPARSEBGP_MINOR_VERSION ${PROJECT_VERSION_PATCH})

option(LIBPARSEBGP_PARSER_DEBUG "Enable parser debug info" OFF)

add_subdirectory(lib)
add_subdirectory(tools)
