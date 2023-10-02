file(GLOB_RECURSE sources ${CMAKE_SOURCE_DIR}/src/*.cpp)
idf_component_register(
        SRCS ${CMAKE_SOURCE_DIR}/test/main.cpp ${sources}
        INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/src
        REQUIRES mittelib libspookyaction unity)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    SPOOKY_HSU
    PN532_SERIAL_TX=17
    PN532_SERIAL_RX=18
)
