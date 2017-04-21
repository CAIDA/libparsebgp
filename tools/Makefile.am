AM_CPPFLAGS =  -I$(top_srcdir)/include

dist_bin_SCRIPTS =

# TODO: come up with a better name for our tool
bin_PROGRAMS = parsebgp

# TODO: rename this source file
parsebgp_SOURCES = \
	bmptool.cpp
parsebgp_LDADD = -lparsebgp
parsebgp_LDFLAGS = -L$(top_builddir)/src

CLEANFILES = *~
