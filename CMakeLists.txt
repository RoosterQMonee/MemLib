cmake_minimum_required(VERSION 3.24)
project(MemLib VERSION 1.0.0 LANGUAGES CXX)

# Enable C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
FetchContent_Declare(
        MinHook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG origin/master
)

# Configure MinHook with modern CMake practices
FetchContent_MakeAvailable(MinHook)

# Get all header files
file(GLOB HEADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

# Get all source files
file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

# Create DLL target
add_library(MemLib MODULE
        ${HEADER_FILES}
        ${SOURCE_FILES}
)

# Add ALL necessary include directories
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(MemLib PRIVATE
        ${INCLUDE_DIR}
        ${MinHook_SOURCE_DIR}/include  # Add MinHook's include directory
)

# Link MinHook
target_link_libraries(${PROJECT_NAME} PRIVATE minhook)
target_include_directories(${PROJECT_NAME}
        PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        PRIVATE ${MinHook_SOURCE_DIR}/include
)

# Set DLL export symbols
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Set Windows-specific properties
set_target_properties(MemLib PROPERTIES
        C_VISIBILITY_PRESET "default"
        VISIBILITY_INLINES_HIDDEN ON
        PREFIX ""
)