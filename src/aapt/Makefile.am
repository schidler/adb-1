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
AM_LDFLAGS = -lz -lpthread ${LIBPNG_LDFLAGS}
