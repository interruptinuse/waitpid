dnl FLAG_ADD will add a language FLAG if the compiler supports it.
dnl
dnl Use these macros as follows:
dnl   FLAG_ADD([CFLAGS], [C], [-Wall])
dnl   # ADDED_CFLAGS="$(build-aux/cleanflags.sh "$ADDED_CFLAGS")" # Optional
dnl   CFLAGS="$ADDED_CFLAGS $CFLAGS"

# FLAG_ADD([FLAGSVAR], [LANG], [PROGRAM], [FLAG], [REQUIREMENT = optional])
# --------------------------------------------------------------
# Test if AC_LANG(LANG) compiler supports insertion of FLAG into
# the configuration variable FLAGSVAR (like CFLAGS).
# If the flag is supported, add it to ADDED_FLAGSVAR (like ADDED_CFLAGS).
# Hard fail if REQUIREMENT is [mandatory].
AC_DEFUN([FLAG_ADD], [
  AC_MSG_CHECKING([whether [$2] [$3] understands [$4]])
  [eval "SAVED_$1"="\"\$$1\""]
  [eval "$1"="\"$4 \$$1\""]
  AC_LANG_PUSH([$2])

  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([],[])],

    AC_MSG_RESULT([yes])
    [eval ADDED_$1="\"$4 \$ADDED_$1\""],

    AC_MSG_RESULT([no])
    AS_CASE([m4_default([$5], [optional])],
    [*mandatory*], [
      AC_MSG_ERROR([[$2] [$3] support for [$4] flag is required!])]))

  [eval "$1"="\"\$SAVED_$1\""]

  AC_LANG_POP()
])
