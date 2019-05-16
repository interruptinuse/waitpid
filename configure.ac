AC_PREREQ([2.60])
AC_INIT([waitpid], [m4_esyscmd_s([cat RELEASE])], [interruptinuse@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign silent-rules])
AC_CONFIG_MACRO_DIRS([m4])


AC_CANONICAL_HOST
dnl AC_PROG_CC
dnl AC_PROG_CC_C99
AC_PROG_CXX
dnl AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])

CXXFLAG_ADD([-Wall])
CXXFLAG_ADD([-Wpedantic])
CXXFLAG_ADD([-Wno-unknown-pragmas])
CXXFLAG_ADD([-Wno-unused-macros])
CXXFLAG_ADD([-Wno-format-security])
CXXFLAG_ADD([-std=c++2a])
CXXFLAG_ADD([-std=c++17])


AS_CASE([$host],
  [*freebsd*], [],
  [*], [
    CXXFLAG_ADD([-flto])
    LDFLAGS="-flto $LDFLAGS"])


AC_MSG_CHECKING([whether we're building for a Win32 host])
AS_CASE([$host],
  [*mingw*|*cygwin*], [
    AC_MSG_RESULT([yes])

    AC_MSG_NOTICE([setting static link flags...])
    LDFLAGS="-static -static-libstdc++ -static-libgcc $LDFLAGS"

    AC_MSG_NOTICE([setting console subsystem...])
    CXXFLAG_ADD([-Wl,--subsystem,console])

    AC_CHECK_TOOL([WINDRES], [windres], AC_MSG_ERROR([windres not found]))
    AC_SUBST([WINDRES])

    AM_CONDITIONAL([WIN32], [true]) ],

  [*], [
    AC_MSG_RESULT([no])

    AX_PTHREAD

    AM_CONDITIONAL([WIN32], [false]) ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT


_cb() {
  tput setaf 240 2>/dev/null || printf ''
  tput bold      2>/dev/null || printf ''
  printf "%s" "$*"
  tput sgr0      2>/dev/null || printf ''
}
echo
echo "***"
echo "$PACKAGE_STRING has been configured:"
echo "  $(_cb host:)     $(printf %-30s "$host"       )  $(_cb build:) $build"
echo "  $(_cb prefix:)   $prefix"
echo "  $(_cb CPP:)      $(printf %-30s "$CPP"        )  $(_cb LD:)    $LD"
echo "  $(_cb CC:)       $(printf %-30s "$CC"         )  $(_cb CXX:)   $CXX"
echo "  $(_cb WINDRES:)  $WINDRES"
echo "  $(_cb CFLAGS:)   $CFLAGS"
echo "  $(_cb CXXFLAGS:) $CXXFLAGS"
echo "  $(_cb PTHREAD_CFLAGS:) $PTHREAD_CFLAGS"
echo "  $(_cb LDFLAGS:)  $(printf %-30s "$LDFLAGS"    )  $(_cb LIBS:)  $LIBS"
echo "  $(_cb PTHREAD_LIBS:) $PTHREAD_LIBS"
echo
