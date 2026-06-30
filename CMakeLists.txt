cmake_minimum_required(VERSION 3.10.0)
project(Note VERSION 0.1.0 LANGUAGES C CXX)

add_executable(Note main.cpp)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED IMPORTED_TARGET gtk4)

target_link_libraries(Note PRIVATE PkgConfig::GTK4)
