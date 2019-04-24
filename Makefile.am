EXTRA_DIST = README RELEASE mingw.thread.h mingw.mutex.h hourglass.ico waitpid.1.in .gitignore

bin_PROGRAMS    = waitpid
dist_man_MANS   = waitpid.1
BUILT_SOURCES   = waitpid.1
CLEANFILES      = waitpid.1

waitpid_SOURCES   = waitpid.cpp


if WIN32
waitpid_DEPENDENCIES  = waitpid.res
waitpid_LDADD         = waitpid.res
CLEANFILES           += waitpid.res

V_WINDRES   = $(V_WINDRES_@AM_V@)
V_WINDRES_  = $(V_WINDRES_@AM_DEFAULT_V@)
V_WINDRES_0 = @echo "  WINDRES  "$@;

waitpid.res: waitpid.rc
	$(V_WINDRES)@WINDRES@ -O coff -o $@ $^
else
waitpid_CXXFLAGS = @PTHREAD_CFLAGS@
waitpid_LDADD    = @PTHREAD_LIBS@
endif

PKG_V_SED   = $(PKG_V_SED_@AM_V@)
PKG_V_SED_  = $(PKG_V_SED_@AM_DEFAULT_V@)
PKG_V_SED_0 = @echo "  SED      "$@;
waitpid.1: waitpid.1.in Makefile
	$(PKG_V_SED)sed \
	  -e 's/[@]PACKAGE_STRING[@]/$(PACKAGE_STRING)/g' \
	  <$< >$@
