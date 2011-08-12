bin_PROGRAMS = adb
AM_CPPFLAGS = -DHAVE_TERMIO_H -I../../include/
AM_LDFLAGS = -lpthread -lz 
adb_DEPENDENCIES = ../../lib/libcutils/libcutils.a ../../lib/libzipfile/libzipfile.a
adb_LDADD = ../../lib/libcutils/libcutils.a ../../lib/libzipfile/libzipfile.a
adb_SOURCES= adb.c \
             services.c \
             transport.c \
	     adb_client.c  \
             transport_local.c \
	     transport_usb.c \
	     commandline.c \
             usb_linux.c  \
	     console.c    \
	     usb_vendors.c \
	     fdevent.c     \
	     utils.c \
	     file_sync_client.c \
	     get_my_path_linux.c \
	     sockets.c
