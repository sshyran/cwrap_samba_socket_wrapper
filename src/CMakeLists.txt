project(libsocket_wrapper C)

add_library(socket_wrapper SHARED socket_wrapper.c)
target_include_directories(socket_wrapper
                           PRIVATE
                               ${CMAKE_BINARY_DIR})
target_compile_options(socket_wrapper
                       PRIVATE
                          ${DEFAULT_C_COMPILE_FLAGS}
                          -D_GNU_SOURCE)
target_link_libraries(socket_wrapper
                      PRIVATE ${SWRAP_REQUIRED_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

set_target_properties(socket_wrapper
                      PROPERTIES
                          VERSION ${LIBRARY_VERSION}
                          SOVERSION ${LIBRARY_SOVERSION})
if (DEFINED DEFAULT_LINK_FLAGS)
    set_target_properties(socket_wrapper
                          PROPERTIES
                              LINK_FLAGS ${DEFAULT_LINK_FLAGS})
endif()

install(TARGETS socket_wrapper
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

set(SOCKET_WRAPPER_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}socket_wrapper${CMAKE_SHARED_LIBRARY_SUFFIX}" PARENT_SCOPE)

add_library(socket_wrapper_noop SHARED socket_wrapper_noop.c)
target_include_directories(socket_wrapper_noop
                           PRIVATE
                               ${socket_wrapper_BINARY_DIR}
                           PUBLIC
                               $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                               $<INSTALL_INTERFACE:include>)
target_compile_options(socket_wrapper_noop
                       PRIVATE
                          ${DEFAULT_C_COMPILE_FLAGS}
                          -D_GNU_SOURCE)
target_link_libraries(socket_wrapper_noop
                      PRIVATE ${SWRAP_REQUIRED_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
set_target_properties(socket_wrapper_noop
                      PROPERTIES
                          VERSION ${NOOP_LIBRARY_VERSION}
                          SOVERSION ${NOOP_LIBRARY_SOVERSION})
if (DEFINED DEFAULT_LINK_FLAGS)
    set_target_properties(socket_wrapper_noop
                          PROPERTIES
                              LINK_FLAGS ${DEFAULT_LINK_FLAGS})
endif()

install(TARGETS socket_wrapper_noop
        EXPORT socket_wrapper_noop-config
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(EXPORT socket_wrapper_noop-config
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/socket_wrapper)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/socket_wrapper.h
    DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}
)
