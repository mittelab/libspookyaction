file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        REQUIRES driver mittelib mbedtls)

if(CONFIG_LIBSPOOKY_COVERAGE_ENABLE)
    target_compile_options(${COMPONENT_LIB} PRIVATE --coverage)
endif()
