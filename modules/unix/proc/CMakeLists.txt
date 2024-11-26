cmake_minimum_required(VERSION 3.24)
set(PROJECT_NAME UnixProc)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 11)

add_executable(${PROJECT_NAME} main.cpp prochandler.h prochandler.cpp)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../../CMakeLists.txt)