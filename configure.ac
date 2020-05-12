AC_PREREQ([2.60])
AC_INIT([waitpid], [m4_esyscmd_s([cat RELEASE])], [interruptinuse@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign silent-rules])
AC_CONFIG_MACRO_DIRS([m4])


AC_CANONICAL_HOST
dnl AC_PROG_CC
dnl AC_PROG_CC_C99
AC_PROG_CXX
dnl AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])
AC_PATH_PROG([BASH], [bash])
test z"$BASH" == z && AC_MSG_ERROR([bash not found])

FLAG_ADD([CXXFLAGS], [C++], [compiler], [-Wall])
FLAG_ADD([CXXFLAGS], [C++], [compiler], [-Wpedantic])
FLAG_ADD([CXXFLAGS], [C++], [compiler], [-Wno-unknown-pragmas])
FLAG_ADD([CXXFLAGS], [C++], [compiler], [-Wno-unused-macros])
FLAG_ADD([CXXFLAGS], [C++], [compiler], [-Wno-format-security])
FLAG_ADD([CXXFLAGS], [C++], [compiler], [-std=c++2a])
FLAG_ADD([CXXFLAGS], [C++], [compiler], [-std=c++17])


AS_CASE([$host],
  [*freebsd*], [],
  [*], [
    FLAG_ADD([CXXFLAGS], [C++], [compiler], [-flto])
    FLAG_ADD([LDFLAGS],  [C++], [linker],   [-flto])])


AC_MSG_CHECKING([whether we're building for a Win32 host])
AS_CASE([$host],
  [*mingw*|*cygwin*], [
    AC_MSG_RESULT([yes])

    AC_MSG_NOTICE([setting static link flags...])
    FLAG_ADD([LDFLAGS],  [C++], [linker],   [-static -static-libstdc++ -static-libgcc])

    AC_MSG_NOTICE([setting console subsystem...])
    FLAG_ADD([CXXFLAGS], [C++], [compiler], [-Wl,--subsystem,console])

    AC_CHECK_TOOL([WINDRES], [windres], AC_MSG_ERROR([windres not found]))
    AC_SUBST([WINDRES])

    AM_CONDITIONAL([WIN32], [true]) ],

  [*], [
    AC_MSG_RESULT([no])

    AX_PTHREAD

    AM_CONDITIONAL([WIN32], [false]) ])

CLEANFLAGS([CXXFLAGS])
CLEANFLAGS([LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

m4_include([build-aux/report.ac])
