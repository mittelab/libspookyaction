file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

if(CONFIG_LIBSPOOKY_COVERAGE_ENABLE)
    idf_component_register(
            SRCS ${SOURCES}
            PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/ut
            PRIV_REQUIRES mittelib libspookyaction catch
            WHOLE_ARCHIVE)
else()
    idf_component_register(
            SRCS ${SOURCES}
            PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/ut
            PRIV_REQUIRES mittelib libspookyaction catch)
endif()
