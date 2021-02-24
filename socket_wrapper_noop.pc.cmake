libdir=@CMAKE_INSTALL_FULL_LIBDIR@
includedir=@CMAKE_INSTALL_FULL_INCLUDEDIR@

Name: @PROJECT_NAME@
Description: The socket_wrapper_noop library
Version: @PROJECT_VERSION@
Libs: -L${libdir} -lsocket_wrapper_noop
Cflags: -I${includedir}
