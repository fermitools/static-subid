cmake_minimum_required(VERSION 3.21)

project(static-subid C)

# ##############################################################################
# CMake modules
include(GNUInstallDirs)
include(CheckCCompilerFlag)

# ##############################################################################
# Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
  message(
    FATAL_ERROR
      "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory and run cmake from there."
  )
endif(EXISTS "${LOC_PATH}")

# ##############################################################################
# Compiler Sanity Test
check_c_source_compiles("int main(void) { return 0; }" CAN_COMPILE)
if(NOT CAN_COMPILE)
  message(FATAL_ERROR "C compiler is non-functional")
endif(NOT CAN_COMPILE)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Standard: C${CMAKE_C_STANDARD}")
message(STATUS "Supported C features: ${CMAKE_C_COMPILE_FEATURES}")

# ##############################################################################
# Required Compiler Warnings These warnings help catch common issues
add_compile_options(
  -Werror # Treat all warnings as errors
  -Wall # Enable most warnings
  -Wextra # Enable extra warnings
  -Wpedantic # ISO C conformance warnings
  -Walloca # Warn on suspicious alloca usage
  -Wcast-align # Warn on alignment-affecting casts
  -Wcast-qual # Warn on cast removing const/volatile
  -Wconversion # Implicit conversion warnings
  -Wdisabled-optimization # Optimization disabled
  -Wdouble-promotion # Implicit float-to-double promotion
  -Werror=implicit-function-declaration # Error on implicit declarations
  -Wformat=2 # Enhanced format string warnings
  -Wformat-security # Format security issues
  -Winline # Inline function can't be inlined
  -Wmissing-declarations # Missing declarations
  -Wmissing-field-initializers # Struct fields left uninitialized
  -Wmissing-prototypes # Missing function prototypes
  -Wnested-externs # Nested extern declarations
  -Wnull-dereference # Potential NULL dereferences
  -Wredundant-decls # Redundant declarations
  -Wshadow # Warn on shadowed variables
  -Wsign-conversion # Sign conversion warnings
  -Wstrict-overflow=2 # Overflow detection (level 2)
  -Wstrict-prototypes # Require function prototypes
  -Wundef # Undefined macro in #if
  -Wvla # Variable length arrays discouraged
  -Wwrite-strings # String literals are const
)

# Ensure our behavior modes are defined
add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)

# Additional GCC features (not supported by all compilers)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(
    -Warith-conversion # Implicit conversions in arithmetic
    -Wduplicated-branches # Identical if/else branches
    -Wduplicated-cond # Duplicated conditions in if/else chains
    -Wjump-misses-init # goto skips variable initialization
    -Wlogical-op # Suspicious logical operations
    -Wstringop-overflow # String operations writing past buffer end
    -Wtrampolines # Nested functions requiring executable stack
  )
endif(CMAKE_C_COMPILER_ID STREQUAL "GNU")

# ##############################################################################
# Find our source code version string
if(NOT DEFINED VERSION OR VERSION STREQUAL "")
  execute_process(
    COMMAND git describe --tags --abbrev=0
    OUTPUT_VARIABLE VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT)

  if(GIT_RESULT OR VERSION STREQUAL "")
    message(FATAL_ERROR "Could not identify version")
  endif()
endif()

# ##############################################################################
# Top Level System Variables, these are pretty much a public api
if(NOT DEFINED CMAKE_INSTALL_SYSTEMD_UNITDIR)
  set(CMAKE_INSTALL_SYSTEMD_UNITDIR
      "/usr/lib/systemd/system"
      CACHE PATH "systemd unit directory")
endif(NOT DEFINED CMAKE_INSTALL_SYSTEMD_UNITDIR)

if(NOT DEFINED CMAKE_INSTALL_SYSTEMD_USERUNITDIR)
  set(CMAKE_INSTALL_SYSTEMD_USERUNITDIR
      "/usr/lib/systemd/user"
      CACHE PATH "systemd user unit directory")
endif(NOT DEFINED CMAKE_INSTALL_SYSTEMD_USERUNITDIR)

if(NOT DEFINED CMAKE_INSTALL_POLKIT_RULESDIR)
  set(CMAKE_INSTALL_POLKIT_RULESDIR
      "/usr/share/polkit-1/rules.d"
      CACHE PATH "polkit rules directory")
endif(NOT DEFINED CMAKE_INSTALL_POLKIT_RULESDIR)

if(NOT DEFINED USERMOD_PATH)
  set(USERMOD_PATH
      "/usr/sbin/usermod"
      CACHE PATH "Path to usermod executable")
endif()

if(NOT DEFINED GETSUBIDS_PATH)
  set(GETSUBIDS_PATH
      "/usr/bin/getsubids"
      CACHE PATH "Path to getsubids executable")
endif()

# Don't change this path on folks without good cause
if(NOT DEFINED CONFIG_DIR_PATH)
  set(CONFIG_DIR_PATH
      "${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}"
      CACHE PATH "Path to main config directory")
endif()

if(NOT DEFINED CONFIG_FILE_PATH)
  set(CONFIG_FILE_PATH
      "${CONFIG_DIR_PATH}/${PROJECT_NAME}.conf"
      CACHE PATH "Path to main config file")
endif()

if(NOT DEFINED CONFIG_DROPIN_DIR_PATH)
  set(CONFIG_DROPIN_DIR_PATH
      "${CONFIG_FILE_PATH}.d"
      CACHE PATH "Path to config drop-in directory")
endif()

# ##############################################################################
# Top Level Configuration Variables
if(NOT DEFINED LOGIN_DEFS_PATH) # shadow-utils considers this file a private api
  set(LOGIN_DEFS_PATH
      "/etc/login.defs"
      CACHE PATH "Path to login.defs")
endif()

if(NOT DEFINED MAX_RANGES)
  set(MAX_RANGES
      8388480
      CACHE STRING "Maximum number of ranges per user")
endif()

# ##############################################################################
# Validate Configuration
if(NOT MAX_RANGES MATCHES "^[0-9]+$")
  message(
    FATAL_ERROR
      "MAX_RANGES must be a non-negative integer (got: '${MAX_RANGES}')")
else()
  math(EXPR MAX_RANGES_INT "${MAX_RANGES}")
endif(NOT MAX_RANGES MATCHES "^[0-9]+$")

# ##############################################################################
# task focused cmake
include(config/CMakeLists.txt)
include(docs/CMakeLists.txt)
include(src/CMakeLists.txt)
include(systemd/CMakeLists.txt)
include(test/CMakeLists.txt)

# ##############################################################################
# Print out state summary
message(STATUS "${CMAKE_PROJECT_NAME} - ${VERSION}")
message(STATUS "Compile Time Configuration:")
message(STATUS "  LOGIN_DEFS_PATH         = ${LOGIN_DEFS_PATH}")
message(STATUS "  CONFIG_DIR_PATH         = ${CONFIG_DIR_PATH}")
message(STATUS "  CONFIG_FILE_PATH        = ${CONFIG_FILE_PATH}")
message(STATUS "  CONFIG_DROPIN_DIR_PATH  = ${CONFIG_DROPIN_DIR_PATH}")
message(STATUS "  USERMOD_PATH            = ${USERMOD_PATH}")
message(STATUS "  GETSUBIDS_PATH          = ${GETSUBIDS_PATH}")
message(STATUS "  MAX_RANGES              = ${MAX_RANGES}")
message(STATUS "Special Install Directories:")
message(
  STATUS "  CMAKE_INSTALL_POLKIT_RULESDIR = ${CMAKE_INSTALL_POLKIT_RULESDIR}")
message(
  STATUS "  CMAKE_INSTALL_SYSTEMD_UNITDIR = ${CMAKE_INSTALL_SYSTEMD_UNITDIR}")
message(
  STATUS
    "  CMAKE_INSTALL_SYSTEMD_USERUNITDIR = ${CMAKE_INSTALL_SYSTEMD_USERUNITDIR}"
)
