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

SUBDIRS = bgp bmp mrt

AM_CPPFLAGS =	-I$(top_srcdir)/	\
		-I$(top_srcdir)/lib	\
		-I$(top_srcdir)/lib/bgp \
		-I$(top_srcdir)/lib/bmp	\
		-I$(top_srcdir)/lib/mrt

include_HEADERS = 		\
	parsebgp.h		\
	parsebgp_error.h	\
	parsebgp_opts.h

lib_LTLIBRARIES = libparsebgp.la

libparsebgp_la_SOURCES = 		\
	parsebgp.c			\
	parsebgp.h			\
	parsebgp_error.c		\
	parsebgp_error.h		\
	parsebgp_opts.c			\
	parsebgp_opts.h			\
	parsebgp_utils.c		\
	parsebgp_utils.h

libparsebgp_la_LIBADD = 			\
	$(top_builddir)/lib/bgp/libparsebgp_bgp.la	\
	$(top_builddir)/lib/bmp/libparsebgp_bmp.la	\
	$(top_builddir)/lib/mrt/libparsebgp_mrt.la

libparsebgp_la_LDFLAGS = -version-info @LIBPARSEBGP_SHLIB_CURRENT@:@LIBPARSEBGP_SHLIB_REVISION@:@LIBPARSEBGP_SHLIB_AGE@

CLEANFILES = *~
