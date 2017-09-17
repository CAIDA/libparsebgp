SUBDIRS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/	\
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/lib/bgp

include_HEADERS = 		\
	parsebgp_bmp.h		\
	parsebgp_bmp_opts.h

noinst_LTLIBRARIES = libparsebgp_bmp.la

libparsebgp_bmp_la_SOURCES = 		\
	parsebgp_bmp.c			\
	parsebgp_bmp.h			\
	parsebgp_bmp_opts.c		\
	parsebgp_bmp_opts.h

CLEANFILES = *~
