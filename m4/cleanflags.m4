# CLEANFLAGS([FLAGSVAR])
# ----------------------

AC_DEFUN([CLEANFLAGS], [
  AC_MSG_NOTICE([cleaning $1 up...])
  [eval "ADDED_$1"="\"\$(build-aux/cleanflags.sh \"\$ADDED_$1\")\""]
  [eval "$1"="\"\$ADDED_$1 \$$1\""]])
