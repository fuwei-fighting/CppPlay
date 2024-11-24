cmake_minimum_required(VERSION 3.24)
set(PROJECT_NAME PamAuth)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 11)

add_executable(${PROJECT_NAME} main.cpp pamauth.cpp pamauth.h)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../CMakeLists.txt)

find_package(PkgConfig REQUIRED)
# link pamauth
target_link_libraries(${PROJECT_NAME} PRIVATE -lpam -lpam_misc)