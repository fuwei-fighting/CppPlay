cmake_minimum_required(VERSION 3.24)
set(PROJECT_NAME QtModel)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_executable(${PROJECT_NAME} main.cpp yylabel.cpp yylabel.h)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../../CMakeLists.txt)

find_package(Qt5 COMPONENTS
        Core
        Gui
        Widgets)

target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
)



