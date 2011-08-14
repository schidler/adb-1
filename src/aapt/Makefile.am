bin_PROGRAMS = aapt
aapt_SOURCES = \
	AaptAssets.cpp \
	Command.cpp \
	CrunchCache.cpp \
	FileFinder.cpp \
	Main.cpp \
	Package.cpp \
	StringPool.cpp \
	XMLNode.cpp \
	ResourceTable.cpp \
	Images.cpp \
	Resource.cpp \
    SourcePos.cpp \
    ZipEntry.cpp \
    ZipFile.cpp
AM_CXXFLAGS = -DHAVE_SYS_UIO_H -I../../include ${LIBPNG_CFLAGS}
AM_LDFLAGS = -lz -lpthread -lpng14 -lexpat
aapt_LDADD = ../../lib/libutils/libutils.a ../../lib/libcutils/libcutils.a ../../lib/liblog/liblog.a ../../lib/libhost/libhost.a
