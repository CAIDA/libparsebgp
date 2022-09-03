#
# Copyright (C) 2017 The Regents of the University of California.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

AC_PREREQ([2.71])


# libparsebgp package version
m4_define([PKG_MAJOR_VERSION], [1])
m4_define([PKG_MID_VERSION],   [0])
m4_define([PKG_MINOR_VERSION], [0])

AC_INIT([libparsebgp],[PKG_MAJOR_VERSION.PKG_MID_VERSION.PKG_MINOR_VERSION],[bgpstream-info@caida.org])

# libparsebgp shared library version
# (no relation to pkg version)
# see https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
# If changes break ABI compatability: CURRENT++, REVISION=0, AGE=0
# elseif changes only add to ABI:     CURRENT++, REVISION=0, AGE++
# else changes do not affect ABI:     REVISION++
LIBPARSEBGP_SHLIB_CURRENT=2
LIBPARSEBGP_SHLIB_REVISION=0
LIBPARSEBGP_SHLIB_AGE=0

######################################################################

LT_INIT

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([lib/parsebgp.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

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

AC_SUBST([LIBPARSEBGP_MAJOR_VERSION], PKG_MAJOR_VERSION)
AC_SUBST([LIBPARSEBGP_MID_VERSION],   PKG_MID_VERSION)
AC_SUBST([LIBPARSEBGP_MINOR_VERSION], PKG_MINOR_VERSION)

AC_SUBST([LIBPARSEBGP_SHLIB_CURRENT])
AC_SUBST([LIBPARSEBGP_SHLIB_REVISION])
AC_SUBST([LIBPARSEBGP_SHLIB_AGE])

AC_CONFIG_FILES([Makefile
                lib/Makefile
                lib/parsebgp.h
                lib/bgp/Makefile
                lib/bmp/Makefile
                lib/mrt/Makefile
		tools/Makefile
		])
AC_OUTPUT
