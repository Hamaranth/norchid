cmake_minimum_required(VERSION 3.22)
project(norchid C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(norchid
        norchid.c
        norchid.h)
