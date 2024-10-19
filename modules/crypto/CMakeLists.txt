cmake_minimum_required(VERSION 3.24)
set(PROJECT_NAME Crypto)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 11)

add_executable(${PROJECT_NAME} main.cpp)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../CMakeLists.txt)

find_package(PkgConfig REQUIRED)
# link crypto
pkg_check_modules(CRYPTO libcrypto++)
target_include_directories(${PROJECT_NAME} PRIVATE ${CRYPTO_INCLUDE_DIRS})
target_link_directories(${PROJECT_NAME} PRIVATE ${CRYPTO_LIBRARY_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CRYPTO_LIBRARIES})




