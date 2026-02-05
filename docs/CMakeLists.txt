cmake_minimum_required(VERSION 3.21)
include(GNUInstallDirs)

find_program(ASCIIDOCTOR asciidoctor)
find_program(ASCIIDOC asciidoc)
find_program(A2X a2x)

# ##############################################################################
# Figure out how to build manpages
if(ASCIIDOCTOR)
  message(STATUS "Using asciidoctor for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/static-subid.conf.5
    COMMAND
      ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/static-subid.conf.5
      ${PROJECT_SOURCE_DIR}/docs/static-subid.conf.adoc
    COMMENT "Building static-subid.conf manpage with asciidoctor"
    VERBATIM)
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/static-subid.8
    COMMAND ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/static-subid.8
            ${PROJECT_SOURCE_DIR}/docs/static-subid.adoc
    COMMENT "Building static-subid manpage with asciidoctor"
    VERBATIM)
  add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/static-subid.conf.5
                                    static-subid.8)
elseif(ASCIIDOC AND A2X)
  message(STATUS "Using asciidoc/a2x for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/static-subid.conf.5
    COMMAND ${A2X} --doctype manpage --format manpage -D ${PROJECT_BINARY_DIR}
            ${PROJECT_SOURCE_DIR}/docs/static-subid.conf.adoc
    COMMENT "Building static-subid.conf manpage with a2x"
    VERBATIM)
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/static-subid.8
    COMMAND ${A2X} --doctype manpage --format manpage -D ${PROJECT_BINARY_DIR}
            ${PROJECT_SOURCE_DIR}/docs/static-subid.adoc
    COMMENT "Building static-subid manpage with a2x"
    VERBATIM)
  add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/static-subid.conf.5
                                    ${PROJECT_BINARY_DIR}/static-subid.8)
else()
  message(FATAL_ERROR "Either asciidoctor required for manpages")
endif()

# Install the actual manpage
install(FILES ${PROJECT_BINARY_DIR}/static-subid.conf.5
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)
install(FILES ${PROJECT_BINARY_DIR}/static-subid.8
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
