set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PROJECT_NAME}")

file(GLOB MODULES ${CMAKE_CURRENT_LIST_DIR}/modules/*)
file(GLOB_RECURSE MIDDLEWARES ${CMAKE_CURRENT_LIST_DIR}/middlewares/*)

set(INCLUDE_PATH ${CMAKE_CURRENT_LIST_DIR}/3rdparty
        ${CMAKE_CURRENT_LIST_DIR}/3rdparty/dbg-macro)
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_PATH})

# link project source from project module
set(SOURCE_FILES)
foreach(DIR ${PROJECT_SOURCE_DIR} )
    file(GLOB TEMP_FILES ${DIR}/*.mm ${DIR}/*.m ${DIR}/*.cpp ${DIR}/*.h ${DIR}/*.hpp)
    list(APPEND SOURCE_FILES ${TEMP_FILES})
endforeach()
target_sources(${PROJECT_NAME} PRIVATE ${SOURCE_FILES})

# link ClangFormat
include(ClangFormat)
clangformat_setup(
        ${SOURCE_FILES}
)

# dbg dependency
add_definitions(-DDBG_MACRO_NO_WARNING)