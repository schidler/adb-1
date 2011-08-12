bin_PROGRAMS = fastboot
fastboot_SOURCES = bootimg.c \
		engine.c \
		fastboot.c \
		protocol.c \
		usb_linux.c \
		util_linux.c 
fastboot_LDADD = ../../lib/libzipfile/libzipfile.a
AM_LDFLAGS = -lpthread -lz
AM_CFLAGS = -I../../include

