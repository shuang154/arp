# ARP Spoofer C++ Core - 香橙派部署指南

## 🍊 香橙派优化版 ARP 欺骗工具

### 架构说明
- **C++ 核心**: 高性能数据包处理、ARP攻击、状态管理 (完全并行，无GIL限制)
- **Python 监督者**: 配置管理、Web API、监控 (轻量级)

### 系统要求
- **硬件**: 香橙派 3/4/5 或其他ARM开发板
- **操作系统**: Ubuntu 20.04+ / Debian 11+ / Armbian
- **内存**: 最少1GB RAM
- **网络**: 千兆以太网接口

### 🚀 快速部署

#### 1. 系统准备
```bash
# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# 安装基础依赖
sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    python3-dev \
    python3-pip \
    libzmq3-dev \
    libjsoncpp-dev \
    git \
    vim
```

#### 2. 下载项目
```bash
# 克隆项目
git clone <项目仓库地址>
cd arp_s

# 或上传项目文件到香橙派
```

#### 3. 一键启动
```bash
# 给构建脚本执行权限
chmod +x scripts/build.sh

# 方式1: 交互式启动（推荐新手）
sudo ./scripts/build.sh

# 方式2: 直接指定接口启动
sudo ./scripts/build.sh -i eth0

# 方式3: 后台运行
sudo ./scripts/build.sh -i eth0 -d

# 方式4: 强制重构建
sudo ./scripts/build.sh -f
```

**交互式选择说明:**
- 脚本会自动检测可用网络接口
- 显示接口状态（UP/DOWN）和IP地址
- 自动推荐最佳接口（有默认路由且状态为UP）
- 直接回车选择推荐接口，或输入数字选择其他接口

#### 4. 运行效果
脚本运行时会显示类似如下界面：
```bash
========================================
  ARP Spoofer C++ Core - 香橙派版
========================================
项目路径: /home/zs/文档/projects/arp_s

未指定网络接口，正在检测...

可用网络接口:
  1. end1    [UP] 192.168.1.100/24 (推荐)
  2. wlan0   [DOWN] 无IP

请选择网络接口 (1-2)，直接回车选择推荐接口: 
```

选择接口后，脚本会自动：
- 检查并安装依赖
- 编译C++核心模块  
- 生成优化配置文件
- 启动高性能ARP攻击服务

### 🔧 性能优化

#### ARM处理器优化
```bash
# 检查CPU信息
cat /proc/cpuinfo

# 设置CPU性能模式 (如果支持)
sudo cpufreq-set -g performance

# 调整网络缓冲区
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 配置文件优化 (config.yaml)
```yaml
performance:
  max_worker_threads: 4        # 根据CPU核心数调整
  packet_batch_size: 10        # ARM设备建议较小值
  packet_batch_timeout: 0.1    # 延迟与吞吐的平衡

attack:
  max_concurrent_attacks: 8    # 根据内存调整
  attack_timeout: 30           # ARM设备建议较短时间

cache:
  arp_cache_ttl: 1200         # 减少内存使用
  attack_cache_ttl: 2400
```

### 📊 监控和维护

#### 系统监控
```bash
# 查看运行状态
ps aux | grep python3

# 查看资源使用
htop
iotop

# 查看日志
tail -f logs/arp_spoofer.log
```

#### Web API监控
```bash
# 启用Web API (在config.yaml中)
enable_web_api: true
web_api_port: 8080

# 访问监控面板
curl http://localhost:8080/api/status
```

#### 性能测试
```bash
# C++核心性能测试
cd cpp_core_v2/build
./arp_processor_test  # 如果构建了测试程序

# 网络接口测试
sudo tcpdump -i eth0 arp
```

### 🐛 故障排除

#### 常见问题

1. **编译失败**
```bash
# 检查依赖
cmake --version
python3 --version
pip3 list | grep pybind11

# 重新安装依赖
sudo apt-get install --reinstall build-essential cmake
pip3 install --upgrade pybind11
```

2. **权限问题**
```bash
# 网络接口访问权限
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# 或使用sudo运行
sudo python3 main.py
```

3. **内存不足**
```bash
# 检查内存使用
free -h
sudo dmesg | grep -i memory

# 调整配置减少内存使用
# 在config.yaml中减少max_concurrent_attacks
```

4. **网络接口问题**
```bash
# 查看网络接口
ip link show
ifconfig

# 确保接口名称在config.yaml中正确
```

### 📈 性能指标

#### 预期性能 (香橙派4)
- **数据包处理**: 5000-10000 pps
- **并发攻击**: 8-16个目标
- **内存使用**: 50-100MB
- **CPU使用**: 30-60% (4核心)

#### 性能调优建议
1. **网络优化**: 使用千兆以太网
2. **存储优化**: 使用SSD或高速SD卡
3. **散热**: 确保良好的散热条件
4. **电源**: 使用稳定的5V/3A电源

### 🔒 安全注意事项

#### 网络安全
- 仅在授权网络中使用
- 定期更新系统和依赖
- 监控系统日志

#### 系统安全
```bash
# 禁用不必要的服务
sudo systemctl disable bluetooth
sudo systemctl disable cups

# 配置防火墙
sudo ufw enable
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 8080/tcp  # Web API (如果需要)
```

### 📚 进阶使用

#### 自定义开发
```cpp
// 修改C++核心
cd cpp_core_v2/src
vim arp_processor.cpp

// 重新构建
cd ../build
make -j4
```

#### 集群部署
```bash
# 多设备协调
# 在config.yaml中配置不同的网络段
# 使用统一的攻击协调机制
```

---

### 🤝 支持

如有问题，请检查：
1. 系统日志: `journalctl -u arp-spoofer`
2. 应用日志: `logs/arp_spoofer.log`
3. 系统资源: `htop`, `free -h`, `df -h`
