cmake_minimum_required(VERSION 3.24)
project(MemLib VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
FetchContent_Declare(
        MinHook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG origin/master
)

FetchContent_MakeAvailable(MinHook)

file(GLOB HEADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/example/*.cpp")

add_library(MemLib MODULE
        ${HEADER_FILES}
        ${SOURCE_FILES}
)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(MemLib PRIVATE
        ${INCLUDE_DIR}
        ${MinHook_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE minhook)
target_include_directories(${PROJECT_NAME}
        PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        PRIVATE ${MinHook_SOURCE_DIR}/include
)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

set_target_properties(MemLib PROPERTIES
        C_VISIBILITY_PRESET "default"
        VISIBILITY_INLINES_HIDDEN ON
        PREFIX ""
)