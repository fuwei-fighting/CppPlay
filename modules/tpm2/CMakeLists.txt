cmake_minimum_required(VERSION 3.24)
set(PROJECT_NAME Tpm2)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 11)

add_executable(${PROJECT_NAME} main.c kyss_tpm2.h kyss_tpm2.c log.h pkcs.h)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../CMakeLists.txt)

find_package(PkgConfig REQUIRED)
# link tss
target_link_libraries(${PROJECT_NAME} PRIVATE -ltss2-esys -ltss2-rc -ltss2-tctildr -ltss2-tcti-device)
target_link_libraries(${PROJECT_NAME} PRIVATE -lcmocka)