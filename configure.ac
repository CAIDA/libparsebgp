AC_PREREQ([2.68])

AC_INIT([libparsebgp], [1.0.0], [bgpstream-info@caida.org])

LIBPARSEBGP_MAJOR_VERSION=1
LIBPARSEBGP_MID_VERSION=0
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

# Should we dump information about where parser errors were encountered?
# This is useful when debugging whether an invalid message is really invalid, or
# if there is a bug in the parser as it will dump the file and line number where
# the error code is "thrown".
AC_MSG_CHECKING([whether to output debug information about parse errors])
AC_ARG_ENABLE([parser-debug],
    [AS_HELP_STRING([--enable-parser-debug],
        [enable parser debug info (def=no)])],
    [parser_debug="$enableval"],
    [parser_debug=no])
AC_MSG_RESULT([$parser_debug])
if test x"$parser_debug" = x"yes"; then
    AC_DEFINE([PARSER_DEBUG],[],[Parser Debugging])
fi

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
