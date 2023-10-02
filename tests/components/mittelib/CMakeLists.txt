file(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/lib/mittelib/src/*.cpp)
idf_component_register(
        SRCS ${sources}
        INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/lib/mittelib/include)