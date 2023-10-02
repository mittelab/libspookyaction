file(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/components/unity/Unity/src/*.c)
idf_component_register(
        SRCS ${sources}
        INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/components/unity/Unity/src)