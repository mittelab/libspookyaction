file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/ut
        PRIV_REQUIRES mittelib libspookyaction catch
        WHOLE_ARCHIVE)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    SPOOKY_HSU
    PN532_SERIAL_TX=17
    PN532_SERIAL_RX=18
)
