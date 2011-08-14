#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([Android host toolset], [2.3.4], [zhangn1985@gmail.com])
AC_CONFIG_SRCDIR([include/zipfile/zipfile.h])
AC_CONFIG_HEADERS([config.h])
AC_PROG_RANLIB
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [pthread_create])
# FIXME: Replace `main' with a function in `-lz':
AC_CHECK_LIB([z], [inflateInit2])
PKG_CHECK_MODULES([LIBPNG],[libpng])
# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit dup2 getcwd gethostbyname gettimeofday memset mkdir select socket strchr strdup strerror strpbrk strrchr strtol strtoul])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 lib/libcutils/Makefile
                 lib/libzipfile/Makefile
                 lib/libutils/Makefile
                 lib/libhost/Makefile
                 src/Makefile
                 src/adb/Makefile
                 src/fastboot/Makefile
                 src/aapt/Makefile])
AC_OUTPUT
