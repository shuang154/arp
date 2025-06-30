cmake_minimum_required(VERSION 3.15)
project(arp_spoofer_cpp VERSION 2.0.0)

# C++17标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 优化选项 - 兼容ARM架构（香橙派）
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|aarch64")
    # ARM优化：不使用march=native，避免兼容性问题
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -mcpu=cortex-a53")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
else()
    # x86/x64优化
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
endif()

# 默认为Release模式
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 查找依赖包 - 兼容多种Linux发行版
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# pybind11 - 优先使用系统安装的版本
find_package(pybind11 QUIET)
if(NOT pybind11_FOUND)
    message(STATUS "pybind11 not found via find_package, trying pip install location")
    # 尝试从pip安装位置查找
    execute_process(COMMAND python3 -c "import pybind11; print(pybind11.get_cmake_dir())" 
                    OUTPUT_VARIABLE PYBIND11_CMAKE_DIR 
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(PYBIND11_CMAKE_DIR)
        find_package(pybind11 REQUIRED HINTS ${PYBIND11_CMAKE_DIR})
    else()
        message(FATAL_ERROR "pybind11 not found. Install with: pip3 install pybind11")
    endif()
endif()

# ZeroMQ - 兼容多种安装方式
pkg_check_modules(ZMQ libzmq)
if(NOT ZMQ_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ZMQ REQUIRED zmq)
endif()

# jsoncpp - 兼容多种安装方式
pkg_check_modules(JSONCPP jsoncpp)
if(NOT JSONCPP_FOUND)
    find_package(jsoncpp)
    if(jsoncpp_FOUND)
        set(JSONCPP_LIBRARIES jsoncpp_lib)
        set(JSONCPP_INCLUDE_DIRS ${jsoncpp_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "jsoncpp not found. Install with: sudo apt-get install libjsoncpp-dev")
    endif()
endif()

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${ZMQ_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS}
)

# 源文件
set(CORE_SOURCES
    src/arp_processor.cpp
)

# 创建Python模块
pybind11_add_module(arp_core_cpp 
    src/python_bindings.cpp
    ${CORE_SOURCES}
)

# 链接库
target_link_libraries(arp_core_cpp PRIVATE 
    Threads::Threads
    ${ZMQ_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# 编译选项
target_compile_options(arp_core_cpp PRIVATE 
    ${ZMQ_CFLAGS_OTHER}
    ${JSONCPP_CFLAGS_OTHER}
)

# 链接目录
target_link_directories(arp_core_cpp PRIVATE 
    ${ZMQ_LIBRARY_DIRS}
    ${JSONCPP_LIBRARY_DIRS}
)

# Python模块属性
target_compile_definitions(arp_core_cpp PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})

# 安装规则
install(TARGETS arp_core_cpp DESTINATION .)

# 可选：创建独立可执行文件用于测试
option(BUILD_STANDALONE "Build standalone executable" OFF)

if(BUILD_STANDALONE)
    add_executable(arp_processor_test
        src/main_test.cpp
        ${CORE_SOURCES}
    )
    
    target_link_libraries(arp_processor_test 
        Threads::Threads
        ${ZMQ_LIBRARIES}
        ${JSONCPP_LIBRARIES}
    )
    
    target_compile_options(arp_processor_test PRIVATE 
        ${ZMQ_CFLAGS_OTHER}
        ${JSONCPP_CFLAGS_OTHER}
    )
endif()

# 输出信息
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "ZMQ found: ${ZMQ_FOUND}")
message(STATUS "JSONCPP found: ${JSONCPP_FOUND}")
message(STATUS "Threads found: ${Threads_FOUND}")
message(STATUS "pybind11 found: ${pybind11_FOUND}")
