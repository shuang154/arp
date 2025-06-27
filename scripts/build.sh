#!/bin/bash

# ARP Spoofer Pro - 完整构建和部署脚本 (香橙派 Arch Linux)
# =======================================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPP_DIR="${PROJECT_ROOT}/cpp_core"
PYTHON_DIR="${PROJECT_ROOT}/python_supervisor"
BUILD_DIR="${CPP_DIR}/build"
CONFIG_DIR="${PROJECT_ROOT}/config"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  ARP Spoofer Pro - 香橙派部署脚本${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}项目路径: ${PROJECT_ROOT}${NC}"
echo ""

# 检查系统依赖
check_dependencies() {
    echo -e "${YELLOW}检查系统依赖...${NC}"
    
    local missing_deps=()
    
    if ! command -v cmake &> /dev/null; then
        missing_deps+=("cmake")
    fi
    
    if ! command -v g++ &> /dev/null; then
        missing_deps+=("gcc")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python")
    fi
    
    if ! command -v pip3 &> /dev/null; then
        missing_deps+=("python-pip")
    fi
    
    # 检查开发库
    if ! pkg-config --exists libpcap; then
        missing_deps+=("libpcap")
    fi
    
    if [ ! -f "/usr/include/zmq.hpp" ] && [ ! -f "/usr/local/include/zmq.hpp" ]; then
        missing_deps+=("zeromq" "cppzmq")
    fi
    
    if [ ! -f "/usr/include/rapidjson/rapidjson.h" ]; then
        missing_deps+=("rapidjson")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}缺少以下依赖:${NC}"
        printf '%s\n' "${missing_deps[@]}"
        echo ""
        echo -e "${YELLOW}Arch Linux 安装命令:${NC}"
        echo "sudo pacman -Syu --needed cmake gcc python python-pip libpcap zeromq cppzmq rapidjson pkgconf"
        echo ""
        read -p "是否现在安装这些依赖? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo pacman -Syu --needed cmake gcc python python-pip libpcap zeromq cppzmq rapidjson pkgconf
        else
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✓ 所有依赖已满足${NC}"
}

# 构建C++核心
build_cpp_core() {
    echo -e "${YELLOW}构建C++核心引擎...${NC}"
    
    if [ ! -d "$CPP_DIR" ]; then
        echo -e "${RED}错误: C++源码目录不存在: $CPP_DIR${NC}"
        exit 1
    fi
    
    cd "${CPP_DIR}"
    
    # 清理旧的构建文件
    if [ -d "${BUILD_DIR}" ]; then
        echo "清理旧的构建文件..."
        rm -rf "${BUILD_DIR}"
    fi
    mkdir -p "${BUILD_DIR}"
    
    cd "${BUILD_DIR}"
    
    # 配置CMake
    echo "配置CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Release
    
    # 编译
    echo "开始编译..."
    make -j$(nproc)
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ C++核心引擎编译成功${NC}"
        
        # 检查可执行文件
        if [ -f "arp_core" ]; then
            echo -e "${GREEN}✓ 可执行文件: ${BUILD_DIR}/arp_core${NC}"
        else
            echo -e "${RED}✗ 可执行文件未找到${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ C++核心引擎编译失败${NC}"
        exit 1
    fi
}

# 设置Python环境
setup_python_env() {
    echo -e "${YELLOW}设置Python环境...${NC}"
    
    if [ ! -d "$PYTHON_DIR" ]; then
        echo -e "${RED}错误: Python源码目录不存在: $PYTHON_DIR${NC}"
        exit 1
    fi
    
    cd "${PYTHON_DIR}"
    
    # 检查是否存在虚拟环境
    if [ ! -d "venv" ]; then
        echo "创建Python虚拟环境..."
        python3 -m venv venv
    fi
    
    # 激活虚拟环境
    source venv/bin/activate
    
    # 升级pip
    echo "升级pip..."
    pip install --upgrade pip
    
    # 安装依赖
    if [ -f "requirements.txt" ]; then
        echo "安装Python依赖..."
        pip install -r requirements.txt
    else
        echo "安装基础Python依赖..."
        pip install pyzmq cachetools pyyaml flask flask-cors requests scapy
    fi
    
    echo -e "${GREEN}✓ Python环境设置完成${NC}"
}

# 创建配置文件 - 修复配置参数
create_config() {
    echo -e "${YELLOW}创建配置文件...${NC}"
    
    mkdir -p "${CONFIG_DIR}"
    local config_file="${CONFIG_DIR}/config.yaml"
    
    if [ ! -f "${config_file}" ]; then
        cat > "${config_file}" << 'EOF'
# ARP Spoofer Pro 配置文件 - 香橙派优化版
# ==========================================

# 网络配置
network:
  interface: "wlan0"             # 香橙派网卡接口名
  gateway_ip: "192.168.1.1"     # 网关IP
  target_server: "192.168.1.100" # 目标服务器IP
  target_ports: [80, 443, 8080, 801]  # 监听端口

# IPC通信配置
ipc:
  packet_address: "ipc:///tmp/arp_spoofer_packets.ipc"
  command_address: "ipc:///tmp/arp_spoofer_commands.ipc"

# 性能配置 (香橙派优化)
performance:
  max_worker_threads: 8          # 香橙派4核，每核2线程
  packet_buffer_size: 8388608    # 8MB 数据包缓冲区
  command_timeout: 1000          # 命令超时时间(ms)

# 攻击策略
attack:
  stealth_mode: false            # 隐蔽模式
  attack_timeout: 45             # 攻击超时时间(秒)
  max_concurrent_attacks: 20     # 最大并发攻击数 (香橙派优化)
  cooldown_time: 3600           # 冷却时间(秒)

# 缓存配置
cache:
  arp_cache_ttl: 1800           # ARP缓存TTL(秒)
  attack_cache_ttl: 3600        # 攻击记录TTL(秒)
  target_info_ttl: 7200         # 目标信息TTL(秒)

# 日志配置
logging:
  level: "INFO"                  # 日志级别
  file: "/var/log/arp_spoofer.log"
  max_size: 104857600           # 100MB
  backup_count: 5

# Web API配置
web_api:
  enabled: true                  # 启用Web API
  port: 8080                    # 监听端口
  host: "0.0.0.0"              # 监听所有接口

# 安全配置
security:
  require_root: true            # 需要root权限
  bind_to_cpu: true            # 绑定CPU核心
  memory_limit: 536870912      # 512MB内存限制 (香橙派优化)
EOF
        
        echo -e "${GREEN}✓ 配置文件已创建: ${config_file}${NC}"
    else
        echo -e "${GREEN}✓ 配置文件已存在: ${config_file}${NC}"
    fi
}

# 创建启动脚本 - 修复hostname命令
create_launch_script() {
    local launcher="${PROJECT_ROOT}/scripts/launch.sh"
    
    cat > "${launcher}" << 'EOF'
#!/bin/bash

# ARP Spoofer Pro 启动脚本
# ========================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPP_CORE="${PROJECT_ROOT}/cpp_core/build/arp_core"
PYTHON_SUPERVISOR="${PROJECT_ROOT}/python_supervisor/main.py"
CONFIG_FILE="${PROJECT_ROOT}/config/config.yaml"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "此脚本需要root权限运行"
    echo "请使用: sudo $0 $@"
    exit 1
fi

# 解析命令行参数
INTERFACE=""
DAEMON_MODE=false

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
        -h|--help)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  -i, --interface IFACE    指定网络接口"
            echo "  -d, --daemon            以守护进程模式运行"
            echo "  -h, --help              显示帮助信息"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 检查接口参数
if [ -z "$INTERFACE" ]; then
    echo "错误: 必须指定网络接口"
    echo "可用网络接口:"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
    echo "使用 -h 查看帮助"
    exit 1
fi

# 检查文件是否存在
if [ ! -f "$CPP_CORE" ]; then
    echo "错误: C++核心未找到: $CPP_CORE"
    echo "请先运行构建脚本: sudo ./build.sh"
    exit 1
fi

if [ ! -f "$PYTHON_SUPERVISOR" ]; then
    echo "错误: Python监督者未找到: $PYTHON_SUPERVISOR"
    exit 1
fi

# 启动函数
start_services() {
    echo "启动ARP Spoofer Pro..."
    echo "接口: $INTERFACE"
    echo "配置: $CONFIG_FILE"
    
    # 清理旧的IPC文件
    rm -f /tmp/arp_spoofer_*.ipc
    
    # 启动C++核心
    echo "启动C++核心引擎..."
    if [ "$DAEMON_MODE" = true ]; then
        nohup "$CPP_CORE" "$INTERFACE" > /var/log/arp_spoofer_core.log 2>&1 &
        CPP_PID=$!
        echo "C++核心PID: $CPP_PID"
    else
        "$CPP_CORE" "$INTERFACE" &
        CPP_PID=$!
    fi
    
    # 等待C++核心初始化
    sleep 3
    
    # 启动Python监督者
    echo "启动Python监督者..."
    cd "${PROJECT_ROOT}/python_supervisor"
    source venv/bin/activate
    
    if [ "$DAEMON_MODE" = true ]; then
        nohup python main.py -c "$CONFIG_FILE" > /var/log/arp_spoofer_supervisor.log 2>&1 &
        PYTHON_PID=$!
        echo "Python监督者PID: $PYTHON_PID"
    else
        python main.py -c "$CONFIG_FILE" &
        PYTHON_PID=$!
    fi
    
    # 保存PID
    echo "$CPP_PID" > /tmp/arp_spoofer_core.pid
    echo "$PYTHON_PID" > /tmp/arp_spoofer_supervisor.pid
    
    if [ "$DAEMON_MODE" = true ]; then
        echo "服务已在后台启动"
        echo "查看日志: tail -f /var/log/arp_spoofer_*.log"
        
        # 获取本机IP地址
        LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1)
        if [ -z "$LOCAL_IP" ]; then
            LOCAL_IP="localhost"
        fi
        echo "Web API: http://${LOCAL_IP}:8080/api/status"
    else
        echo "服务已启动，按Ctrl+C停止"
        wait
    fi
}

# 清理函数
cleanup() {
    echo "正在停止服务..."
    
    if [ -f /tmp/arp_spoofer_core.pid ]; then
        CPP_PID=$(cat /tmp/arp_spoofer_core.pid)
        kill -TERM "$CPP_PID" 2>/dev/null || true
        rm -f /tmp/arp_spoofer_core.pid
    fi
    
    if [ -f /tmp/arp_spoofer_supervisor.pid ]; then
        PYTHON_PID=$(cat /tmp/arp_spoofer_supervisor.pid)
        kill -TERM "$PYTHON_PID" 2>/dev/null || true
        rm -f /tmp/arp_spoofer_supervisor.pid
    fi
    
    rm -f /tmp/arp_spoofer_*.ipc
    echo "服务已停止"
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 启动服务
start_services
EOF
    
    chmod +x "${launcher}"
    echo -e "${GREEN}✓ 启动脚本已创建: ${launcher}${NC}"
}

# 添加命令行参数解析
parse_arguments() {
    QUICK_START=false
    FORCE_BUILD=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick|-q)
                QUICK_START=true
                shift
                ;;
            --force|-f)
                FORCE_BUILD=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 显示帮助信息
show_help() {
    echo "ARP Spoofer Pro 构建和部署脚本"
    echo ""
    echo "用法: sudo $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -q, --quick    快速启动模式 (自动构建并运行)"
    echo "  -f, --force    强制重新构建"
    echo "  -h, --help     显示帮助信息"
    echo ""
    echo "示例:"
    echo "  sudo $0 --quick    # 一键构建并启动"
    echo "  sudo $0 --force    # 强制重新构建"
    echo "  sudo $0            # 交互式构建"
}

# 检查是否需要构建
need_build() {
    if [ "$FORCE_BUILD" = true ]; then
        return 0  # 需要构建
    fi
    
    # 检查C++可执行文件是否存在
    if [ ! -f "${BUILD_DIR}/arp_core" ]; then
        return 0  # 需要构建
    fi
    
    # 检查Python虚拟环境是否存在
    if [ ! -d "${PYTHON_DIR}/venv" ]; then
        return 0  # 需要构建
    fi
    
    # 检查配置文件是否存在
    if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
        return 0  # 需要构建
    fi
    
    return 1  # 不需要构建
}

# 运行模式选择
run_mode_selection() {
    if [ "$QUICK_START" = true ]; then
        echo -e "${BLUE}快速启动模式激活${NC}"
        quick_start
        return
    fi
    
    echo -e "${YELLOW}选择运行模式:${NC}"
    echo "1. 仅构建 (编译完成后退出)"
    echo "2. 构建并交互运行 (前台运行，显示日志)"
    echo "3. 构建并后台运行 (守护进程模式)"
    echo "4. 快速启动 (自动检测网络接口并运行)"
    echo ""
    read -p "请选择 (1-4): " -n 1 -r
    echo
    
    case $REPLY in
        1)
            echo -e "${GREEN}构建完成！${NC}"
            echo -e "${BLUE}使用以下命令运行:${NC}"
            echo "sudo ${PROJECT_ROOT}/scripts/launch.sh -i <interface>"
            echo ""
            echo "可用网络接口:"
            ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
            ;;
        2)
            interactive_run
            ;;
        3)
            daemon_run
            ;;
        4)
            quick_start
            ;;
        *)
            echo "无效选择，默认为仅构建模式"
            echo -e "${BLUE}使用以下命令运行:${NC}"
            echo "sudo ${PROJECT_ROOT}/scripts/launch.sh -i <interface>"
            ;;
    esac
}

# 快速启动模式
quick_start() {
    echo -e "${YELLOW}快速启动模式...${NC}"
    
    # 检查root权限
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 需要root权限运行${NC}"
        echo "请使用: sudo $0"
        exit 1
    fi
    
    # 自动检测网络接口
    echo "检测网络接口..."
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [ -z "$INTERFACE" ]; then
        echo "无法自动检测网络接口，请手动选择:"
        ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
        echo ""
        read -p "请输入网络接口名: " INTERFACE
    else
        echo -e "${GREEN}自动检测到默认网络接口: $INTERFACE${NC}"
    fi
    
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}错误: 必须指定网络接口${NC}"
        exit 1
    fi
    
    # 获取本机IP地址
    LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1)
    if [ -z "$LOCAL_IP" ]; then
        LOCAL_IP="localhost"
    fi
    
    echo -e "${BLUE}即将启动ARP Spoofer Pro...${NC}"
    echo "网络接口: $INTERFACE"
    echo "Web API将在: http://${LOCAL_IP}:8080"
    echo ""
    
    # 直接运行启动脚本
    "${PROJECT_ROOT}/scripts/launch.sh" -i "$INTERFACE"
}

# 交互运行模式
interactive_run() {
    echo -e "${YELLOW}启动交互模式...${NC}"
    
    # 检查root权限
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 需要root权限运行${NC}"
        echo "请使用: sudo $0"
        exit 1
    fi
    
    # 检查网络接口
    echo "可用网络接口:"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
    echo ""
    read -p "请输入网络接口名 (例如: eth0): " INTERFACE
    
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}错误: 必须指定网络接口${NC}"
        exit 1
    fi
    
    # 直接运行启动脚本
    "${PROJECT_ROOT}/scripts/launch.sh" -i "$INTERFACE"
}

# 守护进程运行
daemon_run() {
    echo -e "${YELLOW}启动守护进程模式...${NC}"
    
    # 检查root权限
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 需要root权限运行${NC}"
        echo "请使用: sudo $0"
        exit 1
    fi
    
    # 显示可用网络接口
    echo "可用网络接口:"
    ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
    echo ""
    read -p "请输入网络接口名 (例如: eth0): " INTERFACE
    
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}错误: 必须指定网络接口${NC}"
        exit 1
    fi
    
    # 以守护进程模式启动
    "${PROJECT_ROOT}/scripts/launch.sh" -i "$INTERFACE" -d
}

# 主函数
main() {
    # 解析命令行参数
    parse_arguments "$@"
    
    # 检查项目目录结构
    if [ ! -d "$CPP_DIR" ] || [ ! -d "$PYTHON_DIR" ]; then
        echo -e "${RED}错误: 项目目录结构不完整${NC}"
        echo "CPP目录: $CPP_DIR"
        echo "Python目录: $PYTHON_DIR"
        exit 1
    fi
    
    # 检查是否需要构建
    if need_build; then
        echo -e "${YELLOW}需要构建项目...${NC}"
        
        # 执行构建步骤
        check_dependencies
        build_cpp_core
        setup_python_env
        create_config
        create_launch_script
        
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}  构建完成！${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo ""
    else
        echo -e "${GREEN}项目已构建，跳过构建步骤${NC}"
        create_launch_script  # 确保启动脚本是最新的
        echo ""
    fi
    
    # 运行模式选择
    run_mode_selection
}

# 运行主函数
main "$@"