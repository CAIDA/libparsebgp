AM_CPPFLAGS =  -I$(top_srcdir)/include

dist_bin_SCRIPTS =

# TODO: come up with a better name for our tool
bin_PROGRAMS = parsebgp-old parsebgp

parsebgp_old_SOURCES = \
	lib_parse_bgp_tool.c
parsebgp_old_LDADD = -lparsebgp
parsebgp_old_LDFLAGS = -L$(top_builddir)/src

parsebgp_SOURCES = \
	parsebgp.c
parsebgp_LDADD = -lparsebgp
parsebgp_LDFLAGS = -L$(top_builddir)/src

CLEANFILES = *~
