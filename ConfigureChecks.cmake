include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckStructHasMember)
include(CheckPrototypeDefinition)
include(TestBigEndian)

set(SOCKET_WRAPPER_PACKAGE ${PROJECT_NAME})
set(SOCKET_WRAPPER_VERSION ${PROJECT_VERSION})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

function(COMPILER_DUMPVERSION _OUTPUT_VERSION)
    # Remove whitespaces from the argument.
    # This is needed for CC="ccache gcc" cmake ..
    string(REPLACE " " "" _C_COMPILER_ARG "${CMAKE_C_COMPILER_ARG1}")

    execute_process(
        COMMAND
            ${CMAKE_C_COMPILER} ${_C_COMPILER_ARG} -dumpversion
        OUTPUT_VARIABLE _COMPILER_VERSION
    )

    string(REGEX REPLACE "([0-9])\\.([0-9])(\\.[0-9])?" "\\1\\2"
           _COMPILER_VERSION "${_COMPILER_VERSION}")

    set(${_OUTPUT_VERSION} ${_COMPILER_VERSION} PARENT_SCOPE)
endfunction()

if(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)
    compiler_dumpversion(GNUCC_VERSION)
    if (NOT GNUCC_VERSION EQUAL 34)
        set(CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
        check_c_source_compiles(
"void __attribute__((visibility(\"default\"))) test() {}
int main(void){ return 0; }
" WITH_VISIBILITY_HIDDEN)
        unset(CMAKE_REQUIRED_FLAGS)
    endif (NOT GNUCC_VERSION EQUAL 34)
endif(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)

# HEADERS
check_include_file(netinet/tcp_fsm.h HAVE_NETINET_TCP_FSM_H)
check_include_file(sys/filio.h HAVE_SYS_FILIO_H)
check_include_file(sys/signalfd.h HAVE_SYS_SIGNALFD_H)
check_include_file(sys/eventfd.h HAVE_SYS_EVENTFD_H)
check_include_file(sys/timerfd.h HAVE_SYS_TIMERFD_H)
check_include_file(gnu/lib-names.h HAVE_GNU_LIB_NAMES_H)
check_include_file(rpc/rpc.h HAVE_RPC_RPC_H)

# SYMBOLS
set(CMAKE_REQUIRED_FLAGS -D_GNU_SOURCE)
check_symbol_exists(program_invocation_short_name
                    "errno.h"
                    HAVE_PROGRAM_INVOCATION_SHORT_NAME)
unset(CMAKE_REQUIRED_FLAGS)

# FUNCTIONS
check_function_exists(strncpy HAVE_STRNCPY)
check_function_exists(vsnprintf HAVE_VSNPRINTF)
check_function_exists(snprintf HAVE_SNPRINTF)
check_function_exists(signalfd HAVE_SIGNALFD)
check_function_exists(eventfd HAVE_EVENTFD)
check_function_exists(timerfd_create HAVE_TIMERFD_CREATE)
check_function_exists(bindresvport HAVE_BINDRESVPORT)
check_function_exists(accept4 HAVE_ACCEPT4)
check_function_exists(open64 HAVE_OPEN64)
check_function_exists(fopen64 HAVE_FOPEN64)
check_function_exists(getprogname HAVE_GETPROGNAME)
check_function_exists(getexecname HAVE_GETEXECNAME)
check_function_exists(pledge HAVE_PLEDGE)
check_function_exists(_socket HAVE__SOCKET)
check_function_exists(_close HAVE__CLOSE)
check_function_exists(__close_nocancel HAVE___CLOSE_NOCANCEL)

if (UNIX)
    find_library(DLFCN_LIBRARY dl)
    if (DLFCN_LIBRARY)
        list(APPEND _REQUIRED_LIBRARIES ${DLFCN_LIBRARY})
    else()
        check_function_exists(dlopen HAVE_DLOPEN)
        if (NOT HAVE_DLOPEN)
            message(FATAL_ERROR "FATAL: No dlopen() function detected")
        endif()
    endif()

    if (NOT LINUX)
        # libsocket (Solaris)
        check_library_exists(socket getaddrinfo "" HAVE_LIBSOCKET)
        if (HAVE_LIBSOCKET)
            list(APPEND _REQUIRED_LIBRARIES socket)
        endif (HAVE_LIBSOCKET)

        # libnsl/inet_pton (Solaris)
        check_library_exists(nsl inet_pton "" HAVE_LIBNSL)
        if (HAVE_LIBNSL)
            list(APPEND _REQUIRED_LIBRARIES nsl)
        endif (HAVE_LIBNSL)
    endif (NOT LINUX)

    check_function_exists(getaddrinfo HAVE_GETADDRINFO)
endif (UNIX)

# STRUCTS
check_struct_has_member("struct in_pktinfo" ipi_addr "sys/types.h;sys/socket.h;netinet/in.h" HAVE_STRUCT_IN_PKTINFO)
set(CMAKE_REQUIRED_FLAGS -D_GNU_SOURCE)
check_struct_has_member("struct in6_pktinfo" ipi6_addr "sys/types.h;sys/socket.h;netinet/in.h" HAVE_STRUCT_IN6_PKTINFO)
unset(CMAKE_REQUIRED_FLAGS)

# STRUCT MEMBERS
check_struct_has_member("struct sockaddr" sa_len "sys/types.h;sys/socket.h;netinet/in.h" HAVE_STRUCT_SOCKADDR_SA_LEN)
check_struct_has_member("struct msghdr" msg_control "sys/types.h;sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_CONTROL)

# PROTOTYPES
check_prototype_definition(gettimeofday
    "int gettimeofday(struct timeval *tv, struct timezone *tz)"
    "-1"
    "sys/time.h"
    HAVE_GETTIMEOFDAY_TZ)

check_prototype_definition(gettimeofday
    "int gettimeofday(struct timeval *tv, void *tzp)"
    "-1"
    "sys/time.h"
    HAVE_GETTIMEOFDAY_TZ_VOID)

check_prototype_definition(accept
    "int accept(int s, struct sockaddr *addr, Psocklen_t addrlen)"
    "-1"
    "sys/types.h;sys/socket.h"
    HAVE_ACCEPT_PSOCKLEN_T)

check_prototype_definition(ioctl
    "int ioctl(int s, int r, ...)"
    "-1"
    "unistd.h;sys/ioctl.h"
    HAVE_IOCTL_INT)

if (HAVE_EVENTFD)
    check_prototype_definition(eventfd
        "int eventfd(unsigned int count, int flags)"
        "-1"
        "sys/eventfd.h"
        HAVE_EVENTFD_UNSIGNED_INT)
endif (HAVE_EVENTFD)

# IPV6
check_c_source_compiles("
    #include <stdlib.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <net/if.h>

int main(void) {
    struct sockaddr_storage sa_store;
    struct addrinfo *ai = NULL;
    struct in6_addr in6addr;
    int idx = if_nametoindex(\"iface1\");
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    int ret = getaddrinfo(NULL, NULL, NULL, &ai);
    if (ret != 0) {
        const char *es = gai_strerror(ret);
    }

    freeaddrinfo(ai);
    {
        int val = 1;
#ifdef HAVE_LINUX_IPV6_V6ONLY_26
#define IPV6_V6ONLY 26
#endif
        ret = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                         (const void *)&val, sizeof(val));
    }

    return 0;
}" HAVE_IPV6)

check_c_source_compiles("
#include <sys/socket.h>

int main(void) {
    struct sockaddr_storage s;

    return 0;
}" HAVE_SOCKADDR_STORAGE)

###########################################################
# For detecting attributes we need to treat warnings as
# errors
set(CMAKE_REQUIRED_FLAGS "-Werror")

check_c_source_compiles("
void test_constructor_attribute(void) __attribute__ ((constructor));

void test_constructor_attribute(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_CONSTRUCTOR_ATTRIBUTE)

check_c_source_compiles("
void test_destructor_attribute(void) __attribute__ ((destructor));

void test_destructor_attribute(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_DESTRUCTOR_ATTRIBUTE)

check_c_source_compiles("
#pragma init (test_constructor)
void test_constructor(void);

void test_constructor(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_PRAGMA_INIT)

check_c_source_compiles("
#pragma fini (test_destructor)
void test_destructor(void);

void test_destructor(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_PRAGMA_FINI)

check_c_source_compiles("
#define FALL_THROUGH __attribute__((fallthrough))

int main(void) {
    int i = 2;

    switch (i) {
    case 0:
        FALL_THROUGH;
    case 1:
        break;
    default:
        break;
    }

    return 0;
}" HAVE_FALLTHROUGH_ATTRIBUTE)

check_c_source_compiles("
__thread int tls;

int main(void) {
    return 0;
}" HAVE_GCC_THREAD_LOCAL_STORAGE)

check_c_source_compiles("
void log_fn(const char *format, ...) __attribute__ ((format (printf, 1, 2)));

int main(void) {
    return 0;
}" HAVE_FUNCTION_ATTRIBUTE_FORMAT)

check_c_source_compiles("
void test_address_sanitizer_attribute(void) __attribute__((no_sanitize_address));

void test_address_sanitizer_attribute(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_ADDRESS_SANITIZER_ATTRIBUTE)

# Stop treating wanrings as errors
unset(CMAKE_REQUIRED_FLAGS)
###########################################################

if (OSX)
    set(HAVE_APPLE 1)
endif (OSX)

# ENDIAN
if (NOT WIN32)
    test_big_endian(WORDS_BIGENDIAN)
endif (NOT WIN32)

check_type_size(pid_t SIZEOF_PID_T)

set(SWRAP_REQUIRED_LIBRARIES ${_REQUIRED_LIBRARIES} CACHE INTERNAL "socket_wrapper required system libraries")
