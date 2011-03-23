dnl configure.in for arpscan.

AC_INIT([arpscan], 0.5)
AM_INIT_AUTOMAKE([no-define foreign])

dnl Initialize prefix.
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi

AC_CONFIG_HEADERS([config.h])

dnl Checks for programs.
AC_PROG_CC

dnl Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval -lpcap"
     elif test -f $withval/include/pcap.h -a \
	       -f $withval/include/net/bpf.h; then
	owd=`pwd`
	if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval/include"
	if test -f $withval/lib/libwpcap.a; then
	   PCAPLIB="-L$withval/lib -lwpcap"
	else
	   PCAPLIB="-L$withval/lib -lpcap"
        fi
     else
        AC_ERROR(pcap.h, net/bpf.h, or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

dnl Checks for (installed) libdnet
AC_ARG_WITH(libdnet,
[  --with-libdnet=DIR      use libdnet in DIR],
[ case "$withval" in
  yes|no)
     AC_ERROR([Please specify directory containing dnet-config when using --with-libdnet])
     ;;
  *)
     AC_MSG_CHECKING(for libdnet)
     AC_MSG_RESULT($withval)
     if test -f $withval/src/libdnet.a; then
        DNETINC="-I$withval/include"
        DNETLIB="-L$withval/src -ldnet `$withval/dnet-config --libs`"
     elif test -x $withval/bin/dnet-config; then
        DNETINC="`$withval/bin/dnet-config --cflags`"
        DNETLIB="`$withval/bin/dnet-config --libs`"
     else
        AC_MSG_RESULT(no)
        AC_ERROR(dnet-config not found in $withval/bin)
     fi
     ;;
  esac
  AC_MSG_RESULT(yes) ],
[ dnl This is the default case so let's just use AC_PATH_PROG! --CPK.
  AC_PATH_PROG(dnetconfig, dnet-config, "no")
  if test "$dnetconfig" = "no"; then
     AC_ERROR(dnet-config not found)
  else
     DNETINC="`$dnetconfig --cflags`"
     DNETLIB="`$dnetconfig --libs`"
  fi]
)

dnl We still need to check whether it's dnet or dumbnet as
dnl for example on Debian. We test by looking at the content
dnl of DNETLIB and derive from the library name what version
dnl we're dealing with. If we find a libdumbnet, we prefix
dnl compat/libdnet to our inclusion path. It provides a dnet.h
dnl that transparently includes dumbnet.h for those systems. --CPK.
AC_MSG_CHECKING([whether libdnet is a libdumbnet])
if test `echo $DNETLIB | sed -e '/dumb/=;d'`; then
     AC_MSG_RESULT(yes)
     AC_DEFINE(DUMBNET, 1,
                [Define if our libdnet is a libdumbnet])
     DNETCOMPAT="compat/libdnet"
else
     AC_MSG_RESULT(no)
fi

AC_SUBST(DNETINC)
AC_SUBST(DNETLIB)


dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
