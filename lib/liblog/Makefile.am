noinst_LIBRARIES = liblog.a
liblog_a_SOURCES = logd_write.c \
		  logprint.c \
	        event_tag_map.c \
	        fake_log_device.c
AM_CFLAGS = -DFAKE_LOG_DEVICE=1 -DHAVE_PTHREADS -I../../include -DHAVE_SYS_UIO_H
AM_LDFLAGS = lpthread
