cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tests)

list(APPEND EXTRA_COMPONENT_DIRS "${PROJECT_DIR}/libspookyaction" "${PROJECT_DIR}/tests")

idf_create_coverage_report(${CMAKE_CURRENT_BINARY_DIR}/coverage_report)
idf_clean_coverage_report(${CMAKE_CURRENT_BINARY_DIR}/coverage_report)
