#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([fldr], [1.0], [tewilove@gmail.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_HEADERS([libusb-1.0/libusb.h])
AC_CHECK_LIB(usb-1.0, libusb_open_device_with_vid_pid, [], [AC_MSG_ERROR(libusb-1.0 is not found.)], [])
AC_CHECK_HEADERS([openssl/aes.h])
AC_CHECK_LIB(crypto, AES_cbc_encrypt, [], [AC_MSG_ERROR(OpenSSL is not found.)], [])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strcasecmp])

AC_ARG_ENABLE([static],
    [  --enable-static         build with static linking],
    [LDFLAGS="${LDFLAGS} -static -static-libgcc"])
AM_CONDITIONAL(STATIC, test x"$static" = x"true")

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
