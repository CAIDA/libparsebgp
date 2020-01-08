function(target_public_headers target)
  foreach (arg IN LISTS ARGN)
    if(NOT IS_ABSOLUTE ${arg})
      set(arg "${CMAKE_CURRENT_SOURCE_DIR}/${arg}")
    endif()
    set_property(TARGET ${target} APPEND PROPERTY PUBLIC_HEADER "${arg}")
  endforeach()
endfunction()

add_library(parsebgp)

if(LIBPARSEBGP_PARSER_DEBUG)
    target_compile_definitions(parsebgp PRIVATE PARSER_DEBUG)
endif()

set_target_properties(parsebgp PROPERTIES C_STANDARD 99)

target_include_directories(parsebgp PUBLIC
    $<BUILD_INTERFACE:
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/bgp
        ${CMAKE_CURRENT_SOURCE_DIR}/bmp
        ${CMAKE_CURRENT_SOURCE_DIR}/mrt>)

configure_file(parsebgp.h.in parsebgp.h @ONLY)

target_public_headers(parsebgp
    "${CMAKE_CURRENT_BINARY_DIR}/parsebgp.h"
    parsebgp_error.h
    parsebgp_opts.h
)

target_sources(parsebgp PRIVATE
    parsebgp.c
    parsebgp.h
    parsebgp_error.c
    parsebgp_error.h
    parsebgp_opts.c
    parsebgp_opts.h
    parsebgp_utils.c
    parsebgp_utils.h)

add_subdirectory(bgp)
add_subdirectory(bmp)
add_subdirectory(mrt)

# TODO: Win32 install
include(GNUInstallDirs)

install(
  TARGETS parsebgp
  EXPORT parsebgp
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
