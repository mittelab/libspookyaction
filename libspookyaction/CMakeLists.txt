file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        REQUIRES driver mittelib mbedtls)

target_compile_options(${COMPONENT_LIB} PRIVATE --coverage)
target_link_libraries(${COMPONENT_LIB} PUBLIC gcov)

