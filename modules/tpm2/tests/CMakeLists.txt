
add_executable(${PROJECT_NAME} tests_tpm2.c tests_tpm2.h)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -g)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_11)
find_package(PkgConfig REQUIRED)