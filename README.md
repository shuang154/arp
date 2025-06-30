# ARP Spoofer C++ Core - 高性能多线程版本

🚀 **一键部署：专为消除Python GIL和锁竞争而设计**

## 特性

- ✅ **C++高性能内核**：彻底消除Python GIL限制
- ✅ **多线程无锁设计**：每线程攻击一组IP，完全无锁竞争
- ✅ **真实网络操作**：真实数据包捕获和ARP攻击，无任何模拟
- ✅ **YAML配置驱动**：所有参数通过config.yaml统一管理
- ✅ **一键自动部署**：依赖检测、编译、配置、启动全自动化

## 快速开始

### 🔥 一键部署（推荐）

```bash
# 克隆项目
cd /path/to/your/project

# 一键部署（自动检测网络接口）
sudo ./scripts/build.sh

# 或指定网络接口
sudo ./scripts/build.sh -i wlan0

# 后台运行
sudo ./scripts/build.sh -i wlan0 -d
```

### 🔧 配置说明

所有配置都在自动生成的 `config/config.yaml` 文件中：

```yaml
# 网络配置
network:
  interface: "wlan0"              # 网络接口
  gateway_ip: "192.168.1.1"      # 网关IP

# 性能配置
performance:
  max_worker_threads: 8           # 线程数（自动检测CPU核心数）
  attack_frequency: 10            # 攻击频率

# 攻击配置
attack:
  max_concurrent_attacks: 16      # 最大并发攻击数
  attack_timeout: 30              # 攻击超时时间
```

### 📁 项目结构

```
arp_s/
├── cpp_core/                   # C++高性能内核
│   ├── src/
│   │   ├── arp_spoofer.cpp    # ARP攻击核心
│   │   ├── thread_pool.cpp    # 高性能线程池
│   │   ├── packet_sniffer.cpp # 数据包捕获
│   │   └── python_bindings.cpp # Python绑定
│   └── CMakeLists.txt
├── python_supervisor/          # Python监督者
│   ├── main.py                # 主程序
│   ├── config.py              # 配置管理
│   └── requirements.txt
├── scripts/
│   ├── build.sh               # 🚀 一键部署脚本
│   └── deployment_check.sh    # 可选的快速检查
└── config/
    └── config.yaml            # 🔧 主配置文件（自动生成）
```

## 🔧 高级用法

### 强制重新构建
```bash
sudo ./scripts/build.sh -f
```

### 清理并重新构建
```bash
sudo ./scripts/build.sh -c
```

### 查看帮助
```bash
sudo ./scripts/build.sh -h
```

## 🎯 性能优化特点

1. **消除Python GIL**：核心攻击逻辑完全在C++中实现
2. **无锁设计**：每个线程负责一组IP，避免锁竞争
3. **内存优化**：高效的内存管理和缓存策略
4. **ARM优化**：专为ARM设备优化的参数配置
5. **关闭Web功能**：专注攻击性能，减少资源消耗

## 📋 系统要求

- **操作系统**：Linux（Ubuntu/Debian/Arch/CentOS）
- **权限**：需要root权限进行网络操作
- **依赖**：build.sh会自动检测并安装所有依赖

## 🚨 注意事项

1. **仅用于授权的安全测试**
2. **需要root权限**执行网络操作
3. **配置优先级**：默认值 < YAML配置 < 命令行参数
4. **所有配置以config.yaml为准**，无需额外配置文件

## 📞 支持

- 所有配置通过 `config/config.yaml` 管理
- 日志位于 `logs/arp_spoofer.log`
- 遇到问题请检查依赖安装情况

---

**🔥 核心优势**：通过C++重写消除了Python GIL限制，配合高性能线程池实现真正的并发攻击，系统性能相比纯Python版本有显著提升。