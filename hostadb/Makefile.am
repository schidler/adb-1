bin_PROGRAMS = adb
AM_CPPFLAGS = -O2 -g -DADB_HOST=1  -Wall -Wno-unused-parameter -D_XOPEN_SOURCE -D_GNU_SOURCE -I../include -DHAVE_FORKEXEC
AM_LDFLAGS = -lpthread -lz -lrt -ldl -lssl -lcrypto
adb_LDADD = ../libcutils/libcutils.a ../libzipfile/libzipfile.a
adb_SOURCES = adb.c \
	console.c \
	transport.c \
	transport_local.c \
	transport_usb.c \
	commandline.c \
	adb_client.c \
	adb_auth_host.c \
	sockets.c \
	services.c \
	file_sync_client.c \
	usb_linux.c \
	get_my_path_linux.c \
	utils.c \
	usb_vendors.c \
	fdevent.c
