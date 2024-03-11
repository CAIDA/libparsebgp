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

SUBDIRS =

AM_CPPFLAGS =	-I$(top_srcdir)/	\
		-I$(top_srcdir)/lib	\
		-I$(top_srcdir)/lib/bmp \
		-I$(top_srcdir)/lib/openbmp

include_HEADERS =				\
	parsebgp_bgp.h 				\
	parsebgp_bgp_common.h			\
	parsebgp_bgp_notification.h		\
	parsebgp_bgp_open.h			\
	parsebgp_bgp_opts.h			\
	parsebgp_bgp_route_refresh.h		\
	parsebgp_bgp_update.h			\
	parsebgp_bgp_update_ext_communities.h	\
	parsebgp_bgp_update_mp_reach.h

noinst_LTLIBRARIES = libparsebgp_bgp.la

libparsebgp_bgp_la_SOURCES = 			\
	parsebgp_bgp.c				\
	parsebgp_bgp.h				\
	parsebgp_bgp_common.c			\
	parsebgp_bgp_common.h			\
	parsebgp_bgp_notification.c		\
	parsebgp_bgp_notification.h		\
	parsebgp_bgp_open.c			\
	parsebgp_bgp_open.h			\
	parsebgp_bgp_opts.c			\
	parsebgp_bgp_opts.h			\
	parsebgp_bgp_route_refresh.c		\
	parsebgp_bgp_route_refresh.h		\
	parsebgp_bgp_update.c			\
	parsebgp_bgp_update.h			\
	parsebgp_bgp_update_ext_communities.c	\
	parsebgp_bgp_update_ext_communities.h	\
	parsebgp_bgp_update_mp_reach.c		\
	parsebgp_bgp_update_mp_reach.h		\
	parsebgp_bgp_common_impl.h			\
	parsebgp_bgp_notification_impl.h		\
	parsebgp_bgp_open_impl.h			\
	parsebgp_bgp_route_refresh_impl.h		\
	parsebgp_bgp_update_impl.h			\
	parsebgp_bgp_update_ext_communities_impl.h	\
	parsebgp_bgp_update_mp_reach_impl.h

CLEANFILES = *~
