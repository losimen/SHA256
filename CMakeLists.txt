cmake_minimum_required(VERSION 3.22)
project(SHA256)

set(CMAKE_CXX_STANDARD 11)

add_executable(SHA256 main.cpp SHA256.cpp SHA256.h InfInt.h)
