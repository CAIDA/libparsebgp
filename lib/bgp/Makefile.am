SUBDIRS =

AM_CPPFLAGS =	-I$(top_srcdir)/lib

include_HEADERS = 	parsebgp_bgp.h 		\
			parsebgp_bgp_common.h

noinst_LTLIBRARIES = libparsebgp_bgp.la

libparsebgp_bgp_la_SOURCES = 		\
	evpn.c				\
	evpn.h				\
	ext_community.c			\
	ext_community.h			\
	mp_link_state.c			\
	mp_link_state.h			\
	mp_link_state_attr.c		\
	mp_link_state_attr.h		\
	mp_reach_attr.c			\
	mp_reach_attr.h			\
	mp_un_reach_attr.c		\
	mp_un_reach_attr.h		\
	notification_msg.c		\
	notification_msg.h		\
	open_msg.c			\
	open_msg.h			\
	parsebgp_bgp.c			\
	parsebgp_bgp.h			\
	parsebgp_bgp_common.h		\
	update_msg.c			\
	update_msg.h

CLEANFILES = *~
