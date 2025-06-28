cmake_minimum_required(VERSION 3.16)
project(ARPSpooferCore VERSION 2.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 优化选项
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native -flto")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fsanitize=address")

# 查找依赖库
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED libpcap)

# 查找ZeroMQ
find_path(ZMQ_INCLUDE_DIR zmq.hpp)
find_library(ZMQ_LIBRARY zmq)

if(NOT ZMQ_INCLUDE_DIR OR NOT ZMQ_LIBRARY)
    message(FATAL_ERROR "ZeroMQ not found. Please install libzmq3-dev and cppzmq-dev")
endif()

# 查找RapidJSON
find_path(RAPIDJSON_INCLUDE_DIR rapidjson/rapidjson.h)
if(NOT RAPIDJSON_INCLUDE_DIR)
    message(FATAL_ERROR "RapidJSON not found. Please install rapidjson-dev")
endif()

# ★【新增】★ 查找YAML-cpp
find_library(YAML_CPP_LIBRARY yaml-cpp)
if(NOT YAML_CPP_LIBRARY)
    message(FATAL_ERROR "YAML-cpp not found. Please install libyaml-cpp-dev")
endif()

# 包含目录
include_directories(${LIBPCAP_INCLUDE_DIRS})
include_directories(${ZMQ_INCLUDE_DIR})
include_directories(${RAPIDJSON_INCLUDE_DIR})
include_directories(src)

# 添加源文件
set(SOURCES
    src/main.cpp
    src/packet_sniffer.cpp
    src/arp_spoofer.cpp
    src/ipc_manager.cpp
    src/utils.cpp
    src/config_manager.cpp
)

# 添加头文件
set(HEADERS
    src/packet_sniffer.h
    src/arp_spoofer.h
    src/ipc_manager.h
    src/utils.h
    src/object_pool.h
    src/config_manager.h
    src/graceful_shutdown.h
)

# 创建可执行文件
add_executable(arp_core ${SOURCES} ${HEADERS})

# 链接库
target_link_libraries(arp_core
    ${LIBPCAP_LIBRARIES}
    ${ZMQ_LIBRARY}
    ${YAML_CPP_LIBRARY}  # ★【新增】★ 添加YAML-cpp库
    pthread
)

# 编译选项
target_compile_options(arp_core PRIVATE ${LIBPCAP_CFLAGS_OTHER})

# 安装配置
install(TARGETS arp_core DESTINATION bin)
