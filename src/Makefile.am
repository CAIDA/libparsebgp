SUBDIRS =

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libparsebgp.la

libparsebgp_la_SOURCES = 		\
	add_path_data_container.c 	\
	evpn.c				\
	ext_community.c			\
	mp_link_state.c			\
	mp_link_state_attr.c		\
	mp_reach_attr.c			\
	mp_un_reach_attr.c		\
	notification_msg.c		\
	open_msg.c			\
	parse_bgp.c			\
	parse_bmp.c			\
	parse_mrt.c			\
	parse_utils.c			\
	update_msg.c

libparsebgp_la_LDFLAGS = -version-info @LIBPARSEBGP_MAJOR_VERSION@:@LIBPARSEBGP_MID_VERSION@:@LIBPARSEBGP_MINOR_VERSION@

CLEANFILES = *~
