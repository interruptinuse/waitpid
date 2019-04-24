dnl CXXFLAG_ADD will add a CXXFLAG if the compiler supports it.

AC_DEFUN([CXXFLAG_ADD], [
  AC_MSG_CHECKING([whether C++ compiler understands $1])

  SAVED_CXXFLAGS="$CXXFLAGS"
  CXXFLAGS="$1 $CXXFLAGS"
  AC_LANG_PUSH([C++])

  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([],[])],

    AC_MSG_RESULT([yes]),

    AC_MSG_RESULT([no])
    CXXFLAGS="$SAVED_CXXFLAGS"
  )

  AC_LANG_POP()
])
