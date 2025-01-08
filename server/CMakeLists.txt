cmake_minimum_required(VERSION 3.16)
project(RSA_REST_API)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Manually specify GMP paths
set(GMP_INCLUDE_DIR "/opt/homebrew/opt/gmp/include")
set(GMP_LIBRARIES "/opt/homebrew/opt/gmp/lib/libgmp.dylib")

# Include directories
include_directories(${GMP_INCLUDE_DIRS})

# Add executable
add_executable(RSA_REST_API http_server.cpp rsa_lib.cpp -I/opt/homebrew/include -L/opt/homebrew/lib -lgmp -lgmpxx -std=c++17)

# Link libraries
target_link_libraries(RSA_REST_API ${GMP_LIBRARIES} pthread)
