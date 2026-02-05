cmake_minimum_required(VERSION 3.21)

# ##############################################################################
# Load CMake provided modules
include(GNUInstallDirs)

# ##############################################################################
# Create example configuration file and directory structure
install(DIRECTORY DESTINATION ${CONFIG_DIR_PATH})
install(FILES ${PROJECT_SOURCE_DIR}/config/${PROJECT_NAME}.conf
        DESTINATION ${CONFIG_DIR_PATH})
