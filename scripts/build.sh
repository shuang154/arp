#!/bin/bash

# ARP Spoofer C++ Core - 香橙派一键部署脚本
# =============================================
# 功能：构建、配置、启动（单一脚本完成所有操作）
# 优化：关闭Web功能，专注核心性能

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目路径配置
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPP_DIR="${PROJECT_ROOT}/cpp_core_v2"  # 修正：使用v2版本
PYTHON_DIR="${PROJECT_ROOT}/python_supervisor"
BUILD_DIR="${CPP_DIR}/build"
CONFIG_DIR="${PROJECT_ROOT}/config"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  ARP Spoofer C++ Core - 香橙派版${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}项目路径: ${PROJECT_ROOT}${NC}"
echo ""

# 全局变量
INTERFACE=""
DAEMON_MODE=false
FORCE_BUILD=false

# 显示帮助信息
show_help() {
    echo "ARP Spoofer C++ Core - 一键部署脚本"
    echo ""
    echo "用法: sudo $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -i, --interface IFACE  指定网络接口 (必需)"
    echo "  -d, --daemon          后台运行模式"
    echo "  -f, --force           强制重新构建"
    echo "  -h, --help            显示帮助信息"
    echo ""
    echo "示例:"
    echo "  sudo $0 -i eth0       # 在eth0接口上运行"
    echo "  sudo $0 -i wlan0 -d   # 在wlan0接口上后台运行"
    echo "  sudo $0 -i eth0 -f    # 强制重构建后运行"
    echo ""
    echo "可用网络接口:"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//' 2>/dev/null || echo "  无法获取接口列表"
}

# 解析命令行参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -d|--daemon)
                DAEMON_MODE=true
                shift
                ;;
            -f|--force)
                FORCE_BUILD=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}未知选项: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # 检查必需参数
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}错误: 必须指定网络接口${NC}"
        echo ""
        show_help
        exit 1
    fi
}

# 检查root权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        echo "请使用: sudo $0 $@"
        exit 1
    fi
}

# 检查网络接口
check_interface() {
    if ! ip link show "$INTERFACE" &>/dev/null; then
        echo -e "${RED}错误: 网络接口 '$INTERFACE' 不存在${NC}"
        echo ""
        echo "可用网络接口:"
        ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
        exit 1
    fi
    echo -e "${GREEN}✓ 网络接口 '$INTERFACE' 检查通过${NC}"
}

# 智能依赖检查（支持多种Linux发行版）
check_dependencies() {
    echo -e "${YELLOW}检查系统依赖...${NC}"
    
    local missing_deps=()
    
    # 基础工具检查
    command -v cmake >/dev/null 2>&1 || missing_deps+=("cmake")
    command -v g++ >/dev/null 2>&1 || missing_deps+=("gcc-c++")
    command -v python3 >/dev/null 2>&1 || missing_deps+=("python3")
    command -v pip3 >/dev/null 2>&1 || missing_deps+=("python3-pip")
    command -v pkg-config >/dev/null 2>&1 || missing_deps+=("pkg-config")
    
    # 开发库检查
    if ! pkg-config --exists libzmq 2>/dev/null; then
        missing_deps+=("zeromq-devel")
    fi
    
    if ! pkg-config --exists jsoncpp 2>/dev/null; then
        missing_deps+=("jsoncpp-devel")
    fi
    
    # 检查pybind11
    if ! python3 -c "import pybind11" 2>/dev/null; then
        missing_deps+=("python3-pybind11")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}缺少以下依赖:${NC}"
        printf '  %s\n' "${missing_deps[@]}"
        echo ""
        echo -e "${YELLOW}安装命令建议:${NC}"
        
        # 检测发行版并提供相应的安装命令
        if command -v pacman >/dev/null 2>&1; then
            echo "Arch Linux: sudo pacman -Syu cmake gcc python python-pip zeromq cppzmq jsoncpp"
        elif command -v apt-get >/dev/null 2>&1; then
            echo "Ubuntu/Debian: sudo apt-get install cmake g++ python3-dev python3-pip libzmq3-dev libjsoncpp-dev"
        elif command -v yum >/dev/null 2>&1; then
            echo "CentOS/RHEL: sudo yum install cmake gcc-c++ python3-devel python3-pip zeromq-devel jsoncpp-devel"
        fi
        
        echo ""
        read -p "是否现在自动安装这些依赖? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            auto_install_deps
        else
            echo -e "${RED}请手动安装依赖后重新运行脚本${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✓ 所有依赖已满足${NC}"
}

# 自动安装依赖
auto_install_deps() {
    echo -e "${YELLOW}自动安装依赖...${NC}"
    
    if command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        pacman -Syu --needed cmake gcc python python-pip zeromq cppzmq jsoncpp pkg-config
    elif command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        apt-get update
        apt-get install -y cmake g++ python3-dev python3-pip libzmq3-dev libjsoncpp-dev pkg-config
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL
        yum install -y cmake gcc-c++ python3-devel python3-pip zeromq-devel jsoncpp-devel pkg-config
    else
        echo -e "${RED}无法识别的包管理器，请手动安装依赖${NC}"
        exit 1
    fi
    
    # 安装pybind11
    pip3 install pybind11
}

# 检查是否需要构建
need_build() {
    if [ "$FORCE_BUILD" = true ]; then
        echo -e "${YELLOW}强制重构建模式${NC}"
        return 0  # 需要构建
    fi
    
    # 检查C++模块是否存在
    if [ ! -f "${PYTHON_DIR}/arp_core_cpp"*.so ] && [ ! -f "${PYTHON_DIR}/arp_core_cpp"*.pyd ]; then
        return 0  # 需要构建
    fi
    
    # 检查配置文件是否存在
    if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
        return 0  # 需要构建
    fi
    
    echo -e "${GREEN}✓ 检测到已构建的版本${NC}"
    return 1  # 不需要构建
}

# 构建C++核心
build_cpp_core() {
    echo -e "${YELLOW}构建C++核心...${NC}"
    
    if [ ! -d "$CPP_DIR" ]; then
        echo -e "${RED}错误: C++源码目录不存在: $CPP_DIR${NC}"
        exit 1
    fi
    
    cd "${CPP_DIR}"
    
    # 清理旧的构建文件
    if [ -d "${BUILD_DIR}" ]; then
        echo "清理旧构建..."
        rm -rf "${BUILD_DIR}"
    fi
    mkdir -p "${BUILD_DIR}"
    
    cd "${BUILD_DIR}"
    
    # 配置CMake（ARM优化）
    echo "配置CMake..."
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=17 \
        -DPYTHON_EXECUTABLE=$(which python3)
    
    # 编译（使用所有CPU核心）
    local cpu_cores=$(nproc)
    echo "编译中... (使用 $cpu_cores 核心)"
    make -j"$cpu_cores"
    
    # 检查构建结果
    local built_module=$(find . -name "arp_core_cpp*.so" -o -name "arp_core_cpp*.pyd" | head -1)
    if [ -z "$built_module" ]; then
        echo -e "${RED}✗ 构建失败：未找到Python模块${NC}"
        exit 1
    fi
    
    # 复制到Python目录
    echo "安装模块..."
    cp "$built_module" "${PYTHON_DIR}/"
    
    echo -e "${GREEN}✓ C++核心构建成功${NC}"
    cd "${PROJECT_ROOT}"
}

# 创建高性能配置文件（关闭Web功能）
create_config() {
    echo -e "${YELLOW}创建配置文件...${NC}"
    
    mkdir -p "${CONFIG_DIR}"
    local config_file="${CONFIG_DIR}/config.yaml"
    
    cat > "${config_file}" << EOF
# ARP Spoofer C++ Core 配置文件
# =============================
# 香橙派高性能版本 - Web功能已关闭

# 日志配置
log_level: INFO
log_file: "${PROJECT_ROOT}/logs/arp_spoofer.log"

# 网络配置
network:
  interface: "${INTERFACE}"
  gateway_ip: "192.168.1.1"  # 自动检测或手动配置

# 性能配置（专为ARM优化）
performance:
  max_worker_threads: $(nproc)      # 使用所有CPU核心
  packet_batch_size: 8             # ARM设备适中批次
  packet_batch_timeout: 0.05       # 低延迟

# 攻击配置
attack:
  attack_timeout: 30               # 更短的超时时间
  max_concurrent_attacks: $(( $(nproc) * 2 ))  # 核心数的2倍
  cooldown_time: 1800              # 30分钟冷却

# 缓存配置（内存优化）
cache:
  arp_cache_ttl: 900              # 15分钟
  attack_cache_ttl: 1800          # 30分钟
  target_info_ttl: 3600           # 1小时

# Web API配置（关闭以提升性能）
enable_web_api: false              # 🔥 关闭Web功能，专注性能
web_api_port: 8080                # 保留配置但不启用
EOF
    
    echo -e "${GREEN}✓ 高性能配置文件已创建${NC}"
    echo -e "${BLUE}配置文件位置: ${config_file}${NC}"
}

# 创建日志目录
create_log_dir() {
    local log_dir="${PROJECT_ROOT}/logs"
    mkdir -p "$log_dir"
    chmod 755 "$log_dir"
    echo -e "${GREEN}✓ 日志目录已创建: ${log_dir}${NC}"
}

# 启动服务
start_service() {
    echo -e "${YELLOW}启动ARP Spoofer C++ Core...${NC}"
    
    local config_file="${CONFIG_DIR}/config.yaml"
    local log_file="${PROJECT_ROOT}/logs/arp_spoofer.log"
    
    # 创建日志目录
    create_log_dir
    
    # 清理旧的进程
    cleanup_old_processes
    
    # 进入Python目录
    cd "${PYTHON_DIR}"
    
    # 检查C++模块
    if ! python3 -c "import arp_core_cpp" 2>/dev/null; then
        echo -e "${RED}✗ C++模块加载失败${NC}"
        echo "请检查构建是否成功"
        exit 1
    fi
    
    echo -e "${GREEN}✓ C++模块加载成功${NC}"
    echo -e "${BLUE}网络接口: ${INTERFACE}${NC}"
    echo -e "${BLUE}配置文件: ${config_file}${NC}"
    echo -e "${BLUE}日志文件: ${log_file}${NC}"
    echo ""
    
    # 启动服务
    if [ "$DAEMON_MODE" = true ]; then
        echo -e "${BLUE}启动后台服务...${NC}"
        nohup python3 main.py -c "$config_file" --log-level INFO > "$log_file" 2>&1 &
        local pid=$!
        echo "$pid" > /tmp/arp_spoofer.pid
        
        echo -e "${GREEN}✓ 服务已在后台启动 (PID: $pid)${NC}"
        echo ""
        echo "管理命令:"
        echo "  查看日志: tail -f $log_file"
        echo "  停止服务: sudo kill $pid"
        echo "  检查状态: ps aux | grep $pid"
        
        # 等待几秒检查启动状态
        sleep 3
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${GREEN}✓ 服务运行正常${NC}"
        else
            echo -e "${RED}✗ 服务启动失败，请检查日志${NC}"
            exit 1
        fi
    else
        echo -e "${BLUE}启动前台服务...${NC}"
        echo "按 Ctrl+C 停止服务"
        echo ""
        
        # 设置信号处理
        trap cleanup_and_exit INT TERM
        
        # 前台运行
        python3 main.py -c "$config_file" --log-level INFO
    fi
}

# 清理旧进程
cleanup_old_processes() {
    echo -e "${YELLOW}清理旧进程...${NC}"
    
    # 查找并终止旧的进程
    if [ -f /tmp/arp_spoofer.pid ]; then
        local old_pid=$(cat /tmp/arp_spoofer.pid)
        if kill -0 "$old_pid" 2>/dev/null; then
            echo "终止旧进程 (PID: $old_pid)..."
            kill -TERM "$old_pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$old_pid" 2>/dev/null || true
        fi
        rm -f /tmp/arp_spoofer.pid
    fi
    
    # 清理任何残留进程
    pkill -f "python.*main.py" 2>/dev/null || true
    
    echo -e "${GREEN}✓ 旧进程已清理${NC}"
}

# 清理并退出
cleanup_and_exit() {
    echo ""
    echo -e "${YELLOW}正在停止服务...${NC}"
    cleanup_old_processes
    echo -e "${GREEN}✓ 服务已停止${NC}"
    exit 0
}

# 主函数
main() {
    echo -e "${BLUE}ARP Spoofer C++ Core - 香橙派一键部署脚本${NC}"
    echo ""
    
    # 解析命令行参数
    parse_arguments "$@"
    
    # 基础检查
    check_root
    check_interface
    
    # 检查项目结构
    if [ ! -d "$CPP_DIR" ] || [ ! -d "$PYTHON_DIR" ]; then
        echo -e "${RED}错误: 项目目录结构不完整${NC}"
        echo "C++目录: $CPP_DIR"
        echo "Python目录: $PYTHON_DIR"
        exit 1
    fi
    
    # 构建流程
    if need_build; then
        echo -e "${BLUE}开始构建流程...${NC}"
        check_dependencies
        build_cpp_core
        create_config
        echo -e "${GREEN}✓ 构建完成${NC}"
        echo ""
    else
        echo -e "${GREEN}✓ 跳过构建，使用现有版本${NC}"
        create_config  # 确保配置是最新的
        echo ""
    fi
    
    # 启动服务
    start_service
}

# 运行主函数
main "$@"