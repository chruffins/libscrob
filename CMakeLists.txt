cmake_minimum_required(VERSION 3.16)

project(libscrobbler VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(CURL REQUIRED)

add_library(libscrobbler
	src/client.c
	src/api.c
	src/auth.c
	src/md5.c
	src/scrob.c
	src/scrobble.c
    src/xml.c
)

target_include_directories(libscrobbler
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(libscrobbler
	PUBLIC
		CURL::libcurl
)

add_executable(libscrobbler_harness
	main.c
)

target_link_libraries(libscrobbler_harness
	PRIVATE
		libscrobbler
)