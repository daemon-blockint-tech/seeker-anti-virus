cmake_minimum_required(VERSION 3.22.1)
project(yara_jni)

# libyara source directory (vendored or submodule)
set(LIBYARA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libyara)

# Build libyara from source if available
if(EXISTS "${LIBYARA_DIR}/CMakeLists.txt")
    add_subdirectory(${LIBYARA_DIR} libyara_build)
    set(YARA_LIB yara)
else()
    # Fallback: stub implementation when libyara is not yet vendored
    message(WARNING "libyara not found at ${LIBYARA_DIR}. Building stub. Run ./setup-libyara.sh to vendor libyara.")
    add_library(yara_stub STATIC
        yara_stub.c
    )
    target_include_directories(yara_stub PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    set(YARA_LIB yara_stub)
endif()

# JNI bridge library
add_library(yara_jni SHARED
    yara_jni.cpp
)

find_library(log-lib log)

target_link_libraries(yara_jni
    ${YARA_LIB}
    ${log-lib}
)

target_compile_features(yara_jni PRIVATE cxx_std_17)
