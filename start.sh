#!/bin/bash

# ARP Spoofer 快速启动脚本
# =========================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     ARP Spoofer 快速启动${NC}"
echo -e "${BLUE}========================================${NC}"

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误: 需要root权限${NC}"
    echo "请使用: sudo $0"
    exit 1
fi

# 检查是否已构建
if [ ! -f "${PROJECT_ROOT}/python_supervisor/arp_core_cpp"*.so ]; then
    echo -e "${YELLOW}检测到未构建，启动完整构建流程...${NC}"
    exec "${PROJECT_ROOT}/scripts/build.sh" "$@"
else
    echo -e "${GREEN}✅ 检测到已构建版本，直接启动${NC}"
    
    # 直接启动
    cd "${PROJECT_ROOT}/python_supervisor"
    
    # 检查配置文件
    if [ ! -f "${PROJECT_ROOT}/config/config.yaml" ]; then
        echo -e "${YELLOW}配置文件不存在，创建默认配置...${NC}"
        mkdir -p "${PROJECT_ROOT}/config"
        cat > "${PROJECT_ROOT}/config/config.yaml" << 'EOF'
# 默认配置 - 请根据需要修改
logging:
  level: INFO
  file: "./logs/arp_spoofer.log"

network:
  interface: "wlan0"
  gateway_ip: "10.17.0.1"

web_api:
  enabled: false

performance:
  max_worker_threads: 4

attack:
  attack_frequency: 10
EOF
        echo -e "${GREEN}✅ 默认配置已创建${NC}"
    fi
    
    # 创建日志目录
    mkdir -p "${PROJECT_ROOT}/logs"
    
    # 启动
    echo -e "${BLUE}启动 ARP Spoofer...${NC}"
    python3 main.py -c "${PROJECT_ROOT}/config/config.yaml"
fi
