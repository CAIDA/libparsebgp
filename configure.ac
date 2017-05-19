AC_PREREQ([2.68])

AC_INIT([libparsebgp], [0.1.0], [bgpstream-info@caida.org])

LIBPARSEBGP_MAJOR_VERSION=0
LIBPARSEBGP_MID_VERSION=1
LIBPARSEBGP_MINOR_VERSION=0

AC_DEFINE_UNQUOTED([LIBPARSEBGP_MAJOR_VERSION],$LIBPARSEBGP_MAJOR_VERSION,
	[libparsebgp major version])
AC_DEFINE_UNQUOTED([LIBPARSEBGP_MID_VERSION],$LIBPARSEBGP_MID_VERSION,
	[libparsebgp mid version])
AC_DEFINE_UNQUOTED([LIBPARSEBGP_MINOR_VERSION],$LIBPARSEBGP_MINOR_VERSION,
	[libparsebgp minor version])

LT_INIT

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_MACRO_DIR([m4])

# TODO: change this to libparsebgp.c (or whatever the "main" C file is for the
# library)
AC_CONFIG_SRCDIR([src/parse_bgp.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC_C99
AC_PROG_CXX

# Add C++11 support
# TODO: remove this once we have ported to C
CXXFLAGS="-std=c++11"
#AX_CXX_COMPILE_STDCXX_11

# TODO: add checks for functions/headers that we need (e.g., assert)

AC_SUBST([LIBPARSEBGP_MAJOR_VERSION])
AC_SUBST([LIBPARSEBGP_MID_VERSION])
AC_SUBST([LIBPARSEBGP_MINOR_VERSION])

AC_CONFIG_FILES([Makefile
                include/Makefile
                src/Makefile
		tools/Makefile
		])
AC_OUTPUT
