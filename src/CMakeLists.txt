# ##############################################################################
# Load CMake provided modules

# ##############################################################################
# Generate autoconf.h from template
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/autoconf.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/autoconf.h" @ONLY)

# ##############################################################################
# Source files
set(STATIC_SUBID_LIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/range.c
    ${CMAKE_CURRENT_SOURCE_DIR}/subid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/syscall_ops_default.c
    ${CMAKE_CURRENT_SOURCE_DIR}/util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/validate.c
    CACHE INTERNAL "Library source files")
set(STATIC_SUBID_BINARY_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

# ##############################################################################
# Create executable
add_executable(static-subid ${STATIC_SUBID_BINARY_SOURCES}
                            ${STATIC_SUBID_LIB_SOURCES})

# Compile features (should also be set in parent, but ensure here)
target_compile_features(
  static-subid PRIVATE c_std_23 c_restrict c_function_prototypes
                       c_static_assert)

target_compile_definitions(static-subid PRIVATE _GNU_SOURCE)

# Include directories
target_include_directories(static-subid PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                ${CMAKE_CURRENT_BINARY_DIR})

# ##############################################################################
# Installation
install(TARGETS static-subid RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
