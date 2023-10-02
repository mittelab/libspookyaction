file(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/lib/libspookyaction/src/*.cpp)
idf_component_register(
        SRCS ${sources}
        INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/lib/libspookyaction/include
        REQUIRES driver mittelib mbedtls)

target_compile_options(${COMPONENT_LIB} PRIVATE --coverage)
target_link_libraries(${COMPONENT_LIB} PUBLIC gcov)
