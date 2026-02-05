cmake_minimum_required(VERSION 3.21)

# ##############################################################################
# Load CMake provided modules
include(GNUInstallDirs)

# ##############################################################################
# Create systemd units
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/systemd/system/static-subid@.service.in"
  "${CMAKE_CURRENT_BINARY_DIR}/static-subid@.service" @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/static-subid@.service
        DESTINATION ${CMAKE_INSTALL_SYSTEMD_UNITDIR})
install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/systemd/user/setup-static-subid.service"
  DESTINATION ${CMAKE_INSTALL_SYSTEMD_USERUNITDIR})

# ##############################################################################
# Setup polkit
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/systemd/polkit/50-static-subid.rules"
        DESTINATION ${CMAKE_INSTALL_POLKIT_RULESDIR})

# ##############################################################################
# Setup target
add_custom_target(
  systemd ALL
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/static-subid@.service
  SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/systemd/system/static-subid@.service.in
          ${CMAKE_CURRENT_SOURCE_DIR}/systemd/user/setup-static-subid.service
          ${CMAKE_CURRENT_SOURCE_DIR}/systemd/polkit/50-static-subid.rules)
