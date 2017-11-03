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

libparsebgp_la_LDFLAGS = -version-info @LIBPARSEBGP_MAJOR_VERSION@:@LIBPARSEBGP_MINOR_VERSION@:@LIBPARSEBGP_MID_VERSION@

CLEANFILES = *~
