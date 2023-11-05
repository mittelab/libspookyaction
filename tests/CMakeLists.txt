file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/ut
        PRIV_REQUIRES mittelib libspookyaction catch
        WHOLE_ARCHIVE)
