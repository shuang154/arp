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

# pybind11 - 智能检测多种安装方式
find_package(pybind11 QUIET)
if(NOT pybind11_FOUND)
    message(STATUS "pybind11 not found via find_package, trying alternative locations")
    
    # 方法1: 检查系统pip安装位置
    execute_process(COMMAND python3 -c "import pybind11; print(pybind11.get_cmake_dir())" 
                    OUTPUT_VARIABLE PYBIND11_CMAKE_DIR 
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    
    if(PYBIND11_CMAKE_DIR)
        message(STATUS "Found pybind11 in system Python: ${PYBIND11_CMAKE_DIR}")
        find_package(pybind11 REQUIRED HINTS ${PYBIND11_CMAKE_DIR})
    else()
        # 方法2: 检查项目虚拟环境
        set(VENV_PATH "${CMAKE_SOURCE_DIR}/../venv")
        if(EXISTS "${VENV_PATH}/bin/python")
            message(STATUS "Trying pybind11 in virtual environment: ${VENV_PATH}")
            execute_process(COMMAND ${VENV_PATH}/bin/python -c "import pybind11; print(pybind11.get_cmake_dir())"
                            OUTPUT_VARIABLE VENV_PYBIND11_CMAKE_DIR
                            OUTPUT_STRIP_TRAILING_WHITESPACE
                            ERROR_QUIET)
            
            if(VENV_PYBIND11_CMAKE_DIR)
                message(STATUS "Found pybind11 in venv: ${VENV_PYBIND11_CMAKE_DIR}")
                find_package(pybind11 REQUIRED HINTS ${VENV_PYBIND11_CMAKE_DIR})
            else()
                message(FATAL_ERROR "pybind11 not found in virtual environment. Install with: ${VENV_PATH}/bin/pip install pybind11")
            endif()
        else()
            # 方法3: 提供详细的安装指南
            message(FATAL_ERROR 
                "pybind11 not found. Please install it using one of these methods:\n"
                "  Arch Linux: sudo pacman -S python-pybind11\n"
                "  AUR: yay -S python-pybind11\n"
                "  Pip (system): pip3 install --user pybind11\n"
                "  Pip (venv): python3 -m venv venv && source venv/bin/activate && pip install pybind11")
        endif()
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
