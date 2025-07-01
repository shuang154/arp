cmake_minimum_required(VERSION 3.16)
project(ARPSpooferCore VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 优化选项
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -flto")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fsanitize=address")

# 查找Python和pybind11
# 🔧 优先使用命令行指定的Python解释器
if(PYTHON_EXECUTABLE)
    message(STATUS "Using specified Python executable: ${PYTHON_EXECUTABLE}")
    set(Python_EXECUTABLE ${PYTHON_EXECUTABLE})
endif()

find_package(Python COMPONENTS Interpreter Development REQUIRED)

# 显示使用的Python信息
message(STATUS "Python executable: ${Python_EXECUTABLE}")
message(STATUS "Python version: ${Python_VERSION}")

# 尝试查找pybind11，如果失败则使用pip安装位置
find_package(pybind11 QUIET)
if(NOT pybind11_FOUND)
    message(STATUS "pybind11 not found via find_package, trying pip install location...")
    execute_process(
        COMMAND ${Python_EXECUTABLE} -c "import pybind11; print(pybind11.get_cmake_dir())"
        OUTPUT_VARIABLE pybind11_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE pybind11_RESULT
    )
    if(pybind11_RESULT EQUAL 0)
        find_package(pybind11 REQUIRED PATHS ${pybind11_DIR})
        message(STATUS "Found pybind11 at: ${pybind11_DIR}")
    else()
        message(FATAL_ERROR "pybind11 not found. Please install with: pip install pybind11")
    endif()
endif()

# 查找依赖库
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED libpcap)

# 查找ZeroMQ
find_path(ZMQ_INCLUDE_DIR zmq.hpp)
find_library(ZMQ_LIBRARY zmq)

if(NOT ZMQ_INCLUDE_DIR OR NOT ZMQ_LIBRARY)
    message(FATAL_ERROR "ZeroMQ not found. Please install libzmq3-dev and cppzmq-dev")
endif()

# 直接查找 jsoncpp（不使用 RapidJSON）
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
set(USE_JSONCPP TRUE)
message(STATUS "Found jsoncpp: ${JSONCPP_VERSION}")
message(STATUS "jsoncpp include dirs: ${JSONCPP_INCLUDE_DIRS}")
message(STATUS "jsoncpp libraries: ${JSONCPP_LIBRARIES}")
message(STATUS "jsoncpp library dirs: ${JSONCPP_LIBRARY_DIRS}")

# 包含目录
include_directories(${LIBPCAP_INCLUDE_DIRS})
include_directories(${ZMQ_INCLUDE_DIR})
include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(src)

# 添加库目录
link_directories(${JSONCPP_LIBRARY_DIRS})

# 源文件
set(CORE_SOURCES
    src/packet_sniffer.cpp
    src/arp_spoofer.cpp
    src/ipc_manager.cpp
    src/utils.cpp
    src/thread_pool.cpp
)

# 创建可执行文件（独立运行版本）
add_executable(arp_core src/main.cpp ${CORE_SOURCES})

# 创建Python模块（集成版本）
pybind11_add_module(arp_core_cpp src/python_bindings.cpp ${CORE_SOURCES})

# 链接库 - 可执行文件
target_link_libraries(arp_core
    ${LIBPCAP_LIBRARIES}
    ${ZMQ_LIBRARY}
    ${JSONCPP_LIBRARIES}
    pthread
)

# 链接库 - Python模块
target_link_libraries(arp_core_cpp PRIVATE
    ${LIBPCAP_LIBRARIES}
    ${ZMQ_LIBRARY}
    ${JSONCPP_LIBRARIES}
    pthread
)

# 编译选项
target_compile_options(arp_core PRIVATE ${LIBPCAP_CFLAGS_OTHER})
target_compile_options(arp_core_cpp PRIVATE ${LIBPCAP_CFLAGS_OTHER})

# 安装配置
install(TARGETS arp_core DESTINATION bin)
