# Tested with 3.13, feel free to modify VERSION if you tested it with an older version.
cmake_minimum_required(VERSION 3.13)

function(read_version VERSION_OUTPUT_VAR MAJOR_OUTPUT_VAR MID_OUTPUT_VAR MINOR_OUTPUT_VAR)
    file(READ "${CMAKE_CURRENT_LIST_DIR}/configure.ac" configure)
    string(REGEX MATCH "m4_define\\(\\[PKG_MAJOR_VERSION\\],[^\\[]+\\[([0-9]+)\\]\\)" _ ${configure})
    set(${MAJOR_OUTPUT_VAR} ${CMAKE_MATCH_1})
    string(REGEX MATCH "m4_define\\(\\[PKG_MID_VERSION\\],[^\\[]+\\[([0-9]+)\\]\\)" _ ${configure})
    set(${MID_OUTPUT_VAR} ${CMAKE_MATCH_1})
    string(REGEX MATCH "m4_define\\(\\[PKG_MINOR_VERSION\\],[^\\[]+\\[([0-9]+)\\]\\)" _ ${configure})
    set(${MINOR_OUTPUT_VAR} ${CMAKE_MATCH_1})
    set(${VERSION_OUTPUT_VAR}
        "${${MAJOR_OUTPUT_VAR}}.${${MID_OUTPUT_VAR}}.${${MINOR_OUTPUT_VAR}}")

    foreach(var IN ITEMS
            MAJOR_OUTPUT_VAR MID_OUTPUT_VAR MINOR_OUTPUT_VAR VERSION_OUTPUT_VAR)
        set(${${var}} ${${${var}}} PARENT_SCOPE)
    endforeach()
endfunction()

read_version(
    CONFIGURED_VERSION
    CONFIGURED_MAJOR_VERSION
    CONFIGURED_MID_VERSION
    CONFIGURED_MINOR_VERSION)

project(libparsebgp VERSION ${CONFIGURED_VERSION})

# Check if included as subdirectory
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(LIBPARSEBGP_IS_STANDALONE TRUE)
    set(LIBPARSEBGP_IS_SUBDIRECTORY FALSE)
else()
    set(LIBPARSEBGP_IS_STANDALONE FALSE)
    set(LIBPARSEBGP_IS_SUBDIRECTORY TRUE)
endif()

include(ExternalProject)
ExternalProject_Add(
    libparsebgp_ep
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
    INSTALL_DIR ep_install
    BUILD_IN_SOURCE TRUE
    CONFIGURE_COMMAND ./autogen.sh
        COMMAND ./configure --prefix=<INSTALL_DIR> ${LIBPARSEBGP_EXTRA_CONFIGURE_FLAGS}
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    TEST_COMMAND make check
)

ExternalProject_Get_Property(libparsebgp_ep INSTALL_DIR)

add_library(libparsebgp UNKNOWN IMPORTED)
set_target_properties(
    libparsebgp PROPERTIES
        IMPORTED_LOCATION ${INSTALL_DIR}
        INTERFACE_INCLUDE_DIRECTORIES "${INSTALL_DIR}/include"
        INTERFACE_LINK_DIRECTORIES "${INSTALL_DIR}/lib"
        IMPORTED_LINK_INTERFACE_LIBRARIES "libparsebgp")
    add_dependencies(libparsebgp libparsebgp_ep)

function(libparsebgp_install install_dir)
    install(
        DIRECTORY "${install_dir}/"
        DESTINATION "${CMAKE_INSTALL_PREFIX}"
        USE_SOURCE_PERMISSIONS)
endfunction()

set(LIBPARSEBGP_INSTALL_DIR "${INSTALL_DIR}")

if(LIBPARSEBGP_IS_STANDALONE)
    libparsebgp_install(${LIBPARSEBGP_INSTALL_DIR})
else()
    set(LIBPARSEBGP_INSTALL_DIR "${LIBPARSEBGP_INSTALL_DIR}" PARENT_SCOPE)
endif()
