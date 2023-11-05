cmake_minimum_required(VERSION 3.16)

list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/libspookyaction" "${CMAKE_SOURCE_DIR}/tests")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tests)

if(CONFIG_LIBSPOOKY_COVERAGE_ENABLE)
    idf_create_coverage_report(${CMAKE_CURRENT_BINARY_DIR}/coverage_report)
    idf_clean_coverage_report(${CMAKE_CURRENT_BINARY_DIR}/coverage_report)
endif()
