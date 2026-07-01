cmake_minimum_required(VERSION 3.22.1)
project(shodan_jni)

# JNI bridge library — constructs Shodan API URLs in C++ and delegates
# HTTP requests to Kotlin via a JNI callback interface.
add_library(shodan_jni SHARED
    shodan_jni.cpp
)

find_library(log-lib log)

target_link_libraries(shodan_jni
    ${log-lib}
)

target_compile_features(shodan_jni PRIVATE cxx_std_17)
