# ##############################################################################
# Create example configuration file and directory structure
install(DIRECTORY DESTINATION ${CONFIG_DIR_PATH})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.conf
        DESTINATION ${CONFIG_DIR_PATH})
