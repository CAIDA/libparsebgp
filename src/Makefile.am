SUBDIRS =

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libparsebgp.la

libparsebgp_la_SOURCES = 		\
	add_path_data_container.cpp 	\
	evpn.cpp			\
	ext_community.cpp		\
	mp_link_state.cpp		\
	mp_link_state_attr.cpp		\
	mp_reach_attr.cpp		\
	mp_un_reach_attr.cpp		\
	notification_msg.cpp		\
	open_msg.cpp			\
	parse_bgp.cpp			\
	parse_bmp.cpp			\
	parse_mrt.cpp			\
	parse_utils.cpp			\
	update_msg.cpp

libparsebgp_la_LDFLAGS = -version-info @LIBPARSEBGP_MAJOR_VERSION@:@LIBPARSEBGP_MID_VERSION@:@LIBPARSEBGP_MINOR_VERSION@

CLEANFILES = *~
