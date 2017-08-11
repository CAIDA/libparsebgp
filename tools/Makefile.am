AM_CPPFLAGS =	-I$(top_srcdir)/lib	\
		-I$(top_srcdir)/lib/bgp	\
		-I$(top_srcdir)/lib/bmp	\
		-I$(top_srcdir)/lib/mrt

dist_bin_SCRIPTS =

bin_PROGRAMS = parsebgp

parsebgp_SOURCES = \
	parsebgp.c
parsebgp_LDADD = -lparsebgp
parsebgp_LDFLAGS = -L$(top_builddir)/lib

CLEANFILES = *~
