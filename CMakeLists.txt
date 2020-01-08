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

option(LIBPARSEBGP_PARSER_DEBUG "Enable parser debug info" OFF)

add_subdirectory(lib)
add_subdirectory(tools)
