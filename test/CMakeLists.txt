# ##############################################################################
# Project / modules

include(CTest)
enable_testing()

# ##############################################################################
# Coverage configuration (compiler aware, optional)
#
# Enabled only if tools exist

set(HAVE_COVERAGE_TOOLS OFF)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

  find_program(LCOV_EXEC lcov)
  find_program(GENHTML_EXEC genhtml)

  if(LCOV_EXEC AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS
        -g --coverage -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS --coverage)

    message(STATUS "Coverage enabled: GCC + lcov")
  endif(LCOV_EXEC AND GENHTML_EXEC)

elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

  find_program(LLVM_PROFDATA_EXEC llvm-profdata)
  find_program(LLVM_COV_EXEC llvm-cov)
  find_program(GENHTML_EXEC genhtml)

  if(LLVM_PROFDATA_EXEC
     AND LLVM_COV_EXEC
     AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS
        -g -fprofile-instr-generate -fcoverage-mapping
        -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
        -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS -fprofile-instr-generate)

    message(STATUS "Coverage enabled: Clang + llvm-cov")
  endif(
    LLVM_PROFDATA_EXEC
    AND LLVM_COV_EXEC
    AND GENHTML_EXEC)

endif(CMAKE_C_COMPILER_ID STREQUAL "GNU")

# ##############################################################################
# Helper macros

macro(add_unit_test TEST_NAME)
  add_executable(${TEST_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_NAME}.c ${STATIC_SUBID_LIB_SOURCES})

  target_compile_definitions(${TEST_NAME} PRIVATE _GNU_SOURCE)
  target_compile_features(
    ${TEST_NAME} PRIVATE c_std_23 c_restrict c_function_prototypes
                         c_static_assert)

  target_include_directories(
    ${TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src
                         ${CMAKE_BINARY_DIR}/src)

  target_link_libraries(${TEST_NAME} ${CMAKE_THREAD_LIBS_INIT})

  if(HAVE_COVERAGE_TOOLS)
    target_compile_options(${TEST_NAME} PRIVATE ${COVERAGE_COMPILE_FLAGS})
    target_link_options(${TEST_NAME} PRIVATE ${COVERAGE_LINK_FLAGS})
  endif(HAVE_COVERAGE_TOOLS)

  # keep a record of the binary
  list(APPEND UNIT_TEST_BINARIES ${TEST_NAME})
  # make the list visible to later calls
  set(UNIT_TEST_BINARIES
      "${UNIT_TEST_BINARIES}"
      CACHE INTERNAL "")

  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endmacro(add_unit_test TEST_NAME)

# ##############################################################################
# Tests

if(BUILD_TESTING)
  add_unit_test(test_config)
  add_unit_test(test_range)
  add_unit_test(test_subid)
  add_unit_test(test_util)
  add_unit_test(test_validate)

  add_custom_target(
    test_binaries
    DEPENDS ${UNIT_TEST_BINARIES}
    COMMENT "Building every unit test binary")
endif(BUILD_TESTING)

# ##############################################################################
# Coverage target

if(BUILD_TESTING AND HAVE_COVERAGE_TOOLS)

  set(COVERAGE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/coverage)
  set_property(
    DIRECTORY
    APPEND
    PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_OUTPUT_DIR})

  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

    set(COVERAGE_INFO ${CMAKE_BINARY_DIR}/coverage.info)
    set(COVERAGE_INFO_CLEAN ${CMAKE_BINARY_DIR}/coverage.info.cleaned)
    set_property(
      DIRECTORY
      APPEND
      PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_INFO} ${COVERAGE_INFO_CLEAN})

    add_custom_target(
      coverage
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --zerocounters
      COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --capture --rc
              branch_coverage=1 --output-file ${COVERAGE_INFO}
      COMMAND
        ${LCOV_EXEC} --remove ${COVERAGE_INFO} '${CMAKE_SOURCE_DIR}/test/*' --rc
        branch_coverage=1 --output-file ${COVERAGE_INFO_CLEAN}
      COMMAND ${GENHTML_EXEC} --rc branch_coverage=1 -o ${COVERAGE_OUTPUT_DIR}
              ${COVERAGE_INFO_CLEAN}
      COMMAND ${LCOV_EXEC} --summary ${COVERAGE_INFO_CLEAN} --rc
              branch_coverage=1 --fail-under-lines 95
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating GCC coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

    set(PROFILE_DATA ${CMAKE_BINARY_DIR}/default.profdata)
    set_property(
      DIRECTORY
      APPEND
      PROPERTY ADDITIONAL_CLEAN_FILES ${PROFILE_DATA})

    add_custom_target(
      coverage
      COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=default.profraw
              ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LLVM_PROFDATA_EXEC} merge -sparse default.profraw -o
              ${PROFILE_DATA}
      COMMAND
        ${LLVM_COV_EXEC} show ${UNIT_TEST_BINARIES}
        -instr-profile=${PROFILE_DATA} -format=html
        -output-dir=${COVERAGE_OUTPUT_DIR}
      COMMAND ${LLVM_COV_EXEC} report ${UNIT_TEST_BINARIES}
              -instr-profile=${PROFILE_DATA} -show-region-summary=false
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating Clang coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  endif(CMAKE_C_COMPILER_ID STREQUAL "GNU")

endif(BUILD_TESTING AND HAVE_COVERAGE_TOOLS)
