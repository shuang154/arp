#!/bin/bash

# 依赖安装脚本
# =============

set -e

echo "安装ARP Spoofer Pro依赖..."

# 检测系统类型
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu系统
    echo "检测到Debian/Ubuntu系统"
    sudo apt update
    sudo apt install -y \
        cmake \
        g++ \
        python3 \
        python3-pip \
        python3-venv \
        libpcap-dev \
        libzmq3-dev \
        cppzmq-dev \
        rapidjson-dev \
        pkg-config
        
elif [ -f /etc/redhat-release ]; then
    # CentOS/RHEL/Fedora系统
    echo "检测到RedHat系统"
    sudo yum install -y \
        cmake \
        gcc-c++ \
        python3 \
        python3-pip \
        libpcap-devel \
        zeromq-devel \
        cppzmq-devel \
        rapidjson-devel \
        pkgconfig
        
elif [ -f /etc/arch-release ]; then
    # Arch Linux系统
    echo "检测到Arch Linux系统"
    sudo pacman -S --needed \
        cmake \
        gcc \
        python \
        python-pip \
        libpcap \
        zeromq \
        cppzmq \
        rapidjson \
        pkgconf
        
else
    echo "未知的Linux发行版，请手动安装依赖"
    exit 1
fi

echo "系统依赖安装完成！"
