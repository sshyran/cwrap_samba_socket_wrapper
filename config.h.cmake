/* Name of package */
#cmakedefine SOCKET_WRAPPER_PACKAGE "${SOCKET_WRAPPER_PACKAGE}"

/* Version number of package */
#cmakedefine SOCKET_WRAPPER_VERSION "${SOCKET_WRAPPER_VERSION}"

#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/************************** HEADER FILES *************************/

#cmakedefine HAVE_NETINET_TCP_FSM_H 1
#cmakedefine HAVE_SYS_FILIO_H 1
#cmakedefine HAVE_SYS_SIGNALFD_H 1
#cmakedefine HAVE_SYS_EVENTFD_H 1
#cmakedefine HAVE_SYS_TIMERFD_H 1
#cmakedefine HAVE_GNU_LIB_NAMES_H 1
#cmakedefine HAVE_RPC_RPC_H 1

/**************************** STRUCTS ****************************/

#cmakedefine HAVE_STRUCT_IN_PKTINFO 1
#cmakedefine HAVE_STRUCT_IN6_PKTINFO 1

/************************ STRUCT MEMBERS *************************/

#cmakedefine HAVE_STRUCT_SOCKADDR_SA_LEN 1
#cmakedefine HAVE_STRUCT_MSGHDR_MSG_CONTROL 1

/**************************** SYMBOLS ****************************/

#cmakedefine HAVE_PROGRAM_INVOCATION_SHORT_NAME 1

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `getaddrinfo' function. */
#cmakedefine HAVE_GETADDRINFO 1
#cmakedefine HAVE_SIGNALFD 1
#cmakedefine HAVE_EVENTFD 1
#cmakedefine HAVE_TIMERFD_CREATE 1
#cmakedefine HAVE_BINDRESVPORT 1
#cmakedefine HAVE_ACCEPT4 1
#cmakedefine HAVE_OPEN64 1
#cmakedefine HAVE_FOPEN64 1
#cmakedefine HAVE_GETPROGNAME 1
#cmakedefine HAVE_GETEXECNAME 1
#cmakedefine HAVE_PLEDGE 1
#cmakedefine HAVE__SOCKET 1
#cmakedefine HAVE__CLOSE 1
#cmakedefine HAVE___CLOSE_NOCANCEL 1

#cmakedefine HAVE_ACCEPT_PSOCKLEN_T 1
#cmakedefine HAVE_IOCTL_INT 1
#cmakedefine HAVE_EVENTFD_UNSIGNED_INT 1

/*************************** LIBRARIES ***************************/

#cmakedefine HAVE_GETTIMEOFDAY_TZ 1
#cmakedefine HAVE_GETTIMEOFDAY_TZ_VOID 1

/*************************** DATA TYPES***************************/

#cmakedefine SIZEOF_PID_T @SIZEOF_PID_T@

/**************************** OPTIONS ****************************/

#cmakedefine HAVE_GCC_THREAD_LOCAL_STORAGE 1
#cmakedefine HAVE_CONSTRUCTOR_ATTRIBUTE 1
#cmakedefine HAVE_DESTRUCTOR_ATTRIBUTE 1
#cmakedefine HAVE_PRAGMA_INIT 1
#cmakedefine HAVE_PRAGMA_FINI 1
#cmakedefine HAVE_FALLTHROUGH_ATTRIBUTE 1
#cmakedefine HAVE_ADDRESS_SANITIZER_ATTRIBUTE 1
#cmakedefine HAVE_SOCKADDR_STORAGE 1
#cmakedefine HAVE_IPV6 1
#cmakedefine HAVE_FUNCTION_ATTRIBUTE_FORMAT 1

#cmakedefine HAVE_APPLE 1
#cmakedefine HAVE_LIBSOCKET 1

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1
