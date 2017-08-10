SUBDIRS = include src tools
AM_CPPFLAGS = -I$(top_srcdir)/include

EXTRA_DIST =

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
