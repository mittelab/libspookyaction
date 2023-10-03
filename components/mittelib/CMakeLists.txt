file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/mittelib/src/*.cpp")
idf_component_register(
        SRCS ${SOURCES}
        INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/mittelib/include")