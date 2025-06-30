# 🚀 ARP Spoofer C++ Core - 快速使用指南

## 一键启动（推荐）

```bash
# 1. 进入项目目录
cd arp_s/scripts

# 2. 直接运行（会自动选择网络接口）
sudo ./build.sh
```

## 🍊 香橙派 Arch 系统特别说明

在香橙派的 Arch Linux 系统中，由于 `python-pybind11` 包在官方仓库中不存在，脚本会自动：

1. 安装基础依赖（cmake、gcc、python等）
2. 自动创建虚拟环境并安装 `pybind11`
3. 配置 CMake 使用虚拟环境中的 `pybind11`

这是完全自动化的过程，无需手动干预！

## 预期运行效果

```bash
========================================
  ARP Spoofer C++ Core - 香橙派版
========================================
项目路径: /home/zs/文档/projects/arp_s

未指定网络接口，正在检测...

可用网络接口:
  1. end1    [DOWN] 无IP
  2. wlan0   [UP] 10.17.142.194/16 (推荐)

请选择网络接口 (1-2)，直接回车选择推荐接口: 2
✓ 已选择网络接口: wlan0

✓ 网络接口 'wlan0' 检查通过
开始构建流程...
检查系统依赖...
正在安装 Arch Linux 基础依赖...
✓ 基础依赖安装完成
处理 pybind11 依赖...
pacman 无法安装 python-pybind11（包不存在），创建虚拟环境...
创建虚拟环境: /home/zs/文档/projects/arp_s/venv
✓ 已在虚拟环境中成功安装 pybind11
构建C++核心...
-- Found pybind11 in venv: /home/zs/文档/projects/arp_s/venv/lib/python3.13/site-packages/pybind11/share/cmake/pybind11
-- Build type: Release
-- Configuring done (7.4s)
-- Generating done (0.0s)
编译中... (使用 4 核心)
[ 33%] Building CXX object CMakeFiles/arp_core_cpp.dir/src/python_bindings.cpp.o
[ 66%] Building CXX object CMakeFiles/arp_core_cpp.dir/src/arp_processor.cpp.o
[100%] Linking CXX shared module arp_core_cpp.cpython-313-aarch64-linux-gnu.so
✓ 构建成功
✓ 高性能配置文件已创建
启动ARP Spoofer C++ Core...
✓ C++模块加载成功
网络接口: wlan0
配置文件: /home/zs/文档/projects/arp_s/config/config.yaml
日志文件: /home/zs/文档/projects/arp_s/logs/arp_spoofer.log

启动前台服务...
按 Ctrl+C 停止服务
```

## 其他启动方式

```bash
# 后台运行
sudo ./build.sh -d

# 指定特定接口
sudo ./build.sh -i wlan0

# 强制重新构建
sudo ./build.sh -f

# 查看所有选项
sudo ./build.sh -h
```

## 性能监控

```bash
# 查看日志
tail -f ../logs/arp_spoofer.log

# 查看进程状态  
ps aux | grep python

# 查看系统资源
htop
```

## 停止服务

```bash
# 前台运行：按 Ctrl+C
# 后台运行：
sudo kill $(cat /tmp/arp_spoofer.pid)
```

---

**就是这么简单！** 🎉

从现在开始，你只需要运行 `sudo ./build.sh` 就可以启动整个ARP攻击系统！
