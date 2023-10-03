idf_component_register(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")

set(CATCH_AMALGAMATED_HEADER "${COMPONENT_DIR}/include/catch_amalgamated.hpp")

add_custom_command(
     OUTPUT ${CATCH_AMALGAMATED_HEADER}
     COMMAND curl -L https://github.com/catchorg/Catch2/releases/download/v3.4.0/catch_amalgamated.hpp -o ${CATCH_AMALGAMATED_HEADER}
     VERBATIM)

add_custom_target(download_catch
     DEPENDS ${CATCH_AMALGAMATED_HEADER})

add_dependencies("${COMPONENT_LIB}" download_catch)

set_property(
     DIRECTORY "${COMPONENT_DIR}"
     APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${CATCH_AMALGAMATED_HEADER})
