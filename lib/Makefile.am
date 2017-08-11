SUBDIRS =

AM_CPPFLAGS =

include_HEADERS = 	lib_parse_common.h	\
			parse_bgp.h		\
			parse_bmp.h		\
			parse_mrt.h		\
			parse_utils.h

lib_LTLIBRARIES = libparsebgp.la

libparsebgp_la_SOURCES = 		\
	add_path_data_container.c 	\
	add_path_data_container.h 	\
	evpn.c				\
	evpn.h				\
	ext_community.c			\
	ext_community.h			\
	lib_parse_common.h		\
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
	parse_bgp.c			\
	parse_bgp.h			\
	parse_bmp.c			\
	parse_bmp.h			\
	parse_mrt.c			\
	parse_mrt.h			\
	parse_utils.c			\
	parse_utils.h			\
	update_msg.c			\
	update_msg.h

libparsebgp_la_LDFLAGS = -version-info @LIBPARSEBGP_MAJOR_VERSION@:@LIBPARSEBGP_MID_VERSION@:@LIBPARSEBGP_MINOR_VERSION@

CLEANFILES = *~
