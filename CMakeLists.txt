cmake_minimum_required(VERSION 3.10)
project(lic_client C)

option(BUILD_EXAMPLE "Build the example_client executable" ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED jansson)

set(LIB_SOURCES
    src/lic_client.c
    src/internal/crypto.c
    src/internal/http.c
    src/internal/json_helpers.c
    src/internal/http_handler.c
)


#-----------------------------------------------------------------------------
# Shared Library Target (lic_client_shared -> liblicclient.so/.dll)
#-----------------------------------------------------------------------------
add_library(lic_client_shared SHARED ${LIB_SOURCES})
set_target_properties(lic_client_shared PROPERTIES OUTPUT_NAME "licclient")

if(WIN32)
    target_compile_definitions(lic_client_shared PRIVATE LIC_CLIENT_EXPORTS)
endif()

target_link_libraries(lic_client_shared PRIVATE OpenSSL::SSL OpenSSL::Crypto CURL::libcurl ${JANSSON_LIBRARIES})

target_include_directories(lic_client_shared
    PUBLIC
        # For consumers of the installed library
        $<INSTALL_INTERFACE:include>
        # For consumers within this build (like example_client)
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    PRIVATE
        # Private headers needed only for compiling the library itself
        ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
        ${JANSSON_INCLUDE_DIRS})


#-----------------------------------------------------------------------------
# Static Library Target (lic_client_static -> liblicclient_static.a)
#-----------------------------------------------------------------------------
add_library(lic_client_static STATIC ${LIB_SOURCES})
set_target_properties(lic_client_static PROPERTIES OUTPUT_NAME "licclient_static")

target_compile_definitions(lic_client_static PUBLIC LIC_CLIENT_STATIC_LIB)

target_link_libraries(lic_client_static PRIVATE OpenSSL::SSL OpenSSL::Crypto CURL::libcurl ${JANSSON_LIBRARIES})

target_include_directories(lic_client_static
    PUBLIC
        # For consumers of the installed library
        $<INSTALL_INTERFACE:include>
        # For consumers within this build (like example_client)
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    PRIVATE
        # Private headers needed only for compiling the library itself
        ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
        ${JANSSON_INCLUDE_DIRS})


#-----------------------------------------------------------------------------
# Example Executable
#-----------------------------------------------------------------------------
if(BUILD_EXAMPLE)
    add_executable(example_client main.c)
    target_link_libraries(example_client PRIVATE lic_client_static)
endif()


#-----------------------------------------------------------------------------
# Installation Rules
#-----------------------------------------------------------------------------
install(FILES src/lic_client.h DESTINATION include)

install(TARGETS lic_client_static lic_client_shared
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)

if(BUILD_EXAMPLE)
    install(TARGETS example_client RUNTIME DESTINATION bin)
endif()