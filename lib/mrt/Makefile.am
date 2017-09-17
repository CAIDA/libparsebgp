SUBDIRS =

AM_CPPFLAGS =	-I$(top_srcdir)/	\
		-I$(top_srcdir)/lib	\
		-I$(top_srcdir)/lib/bgp	\
		-I$(top_srcdir)/lib/bmp

include_HEADERS = parsebgp_mrt.h

noinst_LTLIBRARIES = libparsebgp_mrt.la

libparsebgp_mrt_la_SOURCES = 		\
	parsebgp_mrt.c			\
	parsebgp_mrt.h

CLEANFILES = *~
