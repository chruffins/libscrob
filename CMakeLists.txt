cmake_minimum_required(VERSION 3.16)

project(libscrobbler VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(libscrobbler
	src/authentication.c
	src/client.c
	src/md5.c
	src/scrob.c
)

target_include_directories(libscrobbler
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include
)