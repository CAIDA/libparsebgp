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

AC_CONFIG_SRCDIR([lib/parsebgp.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC_C99

# TODO: add checks for functions/headers that we need (e.g., assert)

AC_SUBST([LIBPARSEBGP_MAJOR_VERSION])
AC_SUBST([LIBPARSEBGP_MID_VERSION])
AC_SUBST([LIBPARSEBGP_MINOR_VERSION])

AC_CONFIG_FILES([Makefile
                lib/Makefile
                lib/bgp/Makefile
                lib/bmp/Makefile
                lib/mrt/Makefile
		tools/Makefile
		])
AC_OUTPUT
