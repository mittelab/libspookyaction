idf_component_register(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_command(
     OUTPUT "${COMPONENT_DIR}/include/catch.hpp"
     COMMAND curl -L https://github.com/catchorg/Catch2/releases/download/v3.4.0/catch_amalgamated.hpp -o "${COMPONENT_DIR}/include/catch.hpp"
     VERBATIM)

add_custom_target(download_catch
     DEPENDS "${COMPONENT_DIR}/include/catch.hpp")

add_dependencies("${COMPONENT_LIB}" download_catch)

set_property(
     DIRECTORY "${COMPONENT_DIR}"
     APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${COMPONENT_DIR}/include/catch.hpp")
