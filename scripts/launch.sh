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
