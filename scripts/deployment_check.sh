#!/bin/bash

# 可选的快速部署检查脚本 - 仅用于快速验证
# =============================================
# 注意：build.sh 已包含完整的依赖检测和自动安装功能
#       这个脚本仅用于快速检查，不是必需的

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  ARP Spoofer 快速检查（可选）${NC}"
echo -e "${BLUE}  build.sh 已包含完整部署功能${NC}"
echo -e "${BLUE}========================================${NC}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 快速检查核心文件
echo -e "${YELLOW}检查核心文件...${NC}"
core_files=("${PROJECT_ROOT}/cpp_core/CMakeLists.txt" "${PROJECT_ROOT}/python_supervisor/main.py" "${PROJECT_ROOT}/scripts/build.sh")
all_exist=true

for file in "${core_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}✗ 缺少: $(basename $file)${NC}"
        all_exist=false
    fi
done

if $all_exist; then
    echo -e "${GREEN}✓ 核心文件完整${NC}"
else
    echo -e "${RED}✗ 文件不完整${NC}"
    exit 1
fi

# 快速检查权限
echo -e "${YELLOW}检查权限...${NC}"
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}✓ 具有root权限${NC}"
else
    echo -e "${YELLOW}⚠ 当前无root权限，部署时需要sudo${NC}"
fi

# 检查网络接口
echo -e "${YELLOW}检查网络接口...${NC}"
if command -v ip >/dev/null 2>&1; then
    interfaces=($(ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v "^lo$"))
    
    if [ ${#interfaces[@]} -gt 0 ]; then
        echo -e "${GREEN}✓ 找到 ${#interfaces[@]} 个网络接口${NC}"
        
        # 显示推荐接口
        default_iface=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -n "$default_iface" ]; then
            echo -e "${GREEN}  推荐接口: $default_iface${NC}"
        fi
    else
        echo -e "${RED}✗ 未找到可用网络接口${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ 无法检查网络接口${NC}"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🎉 快速检查完成！${NC}"
echo ""
echo -e "${BLUE}下一步：${NC}"
echo "  sudo ./build.sh              # 自动检测并部署"
echo "  sudo ./build.sh -i wlan0     # 指定wlan0接口部署"
echo "  sudo ./build.sh -i wlan0 -d  # 后台模式部署"
echo ""
echo -e "${YELLOW}注意：build.sh 包含完整的依赖检测、安装、编译和配置功能${NC}"
echo -e "${YELLOW}      这个检查脚本仅用于快速验证，不是必需的${NC}"
echo -e "${BLUE}========================================${NC}"
