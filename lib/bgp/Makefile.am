SUBDIRS =

AM_CPPFLAGS =	-I$(top_srcdir)/lib

include_HEADERS =				\
	parsebgp_bgp.h 				\
	parsebgp_bgp_common.h			\
	parsebgp_bgp_opts.h			\
	parsebgp_bgp_update.h			\
	parsebgp_bgp_update_ext_communities.h	\
	parsebgp_bgp_update_mp_reach.h

noinst_LTLIBRARIES = libparsebgp_bgp.la

libparsebgp_bgp_la_SOURCES = 			\
	parsebgp_bgp.c				\
	parsebgp_bgp.h				\
	parsebgp_bgp_common.h			\
	parsebgp_bgp_opts.h			\
	parsebgp_bgp_update.c			\
	parsebgp_bgp_update.h			\
	parsebgp_bgp_update_ext_communities.c	\
	parsebgp_bgp_update_ext_communities.h	\
	parsebgp_bgp_update_mp_reach.c		\
	parsebgp_bgp_update_mp_reach.h

CLEANFILES = *~
