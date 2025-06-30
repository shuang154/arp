# 🚀 ARP Spoofer C++ Core - 快速使用指南

## 一键启动（推荐）

```bash
# 1. 进入项目目录
cd arp_s/scripts

# 2. 直接运行（会自动选择网络接口）
sudo ./build.sh
```

## 预期运行效果

```bash
========================================
  ARP Spoofer C++ Core - 香橙派版
========================================
项目路径: /home/zs/文档/projects/arp_s

未指定网络接口，正在检测...

可用网络接口:
  1. end1    [UP] 192.168.1.100/24 (推荐)
  2. wlan0   [DOWN] 无IP

请选择网络接口 (1-2)，直接回车选择推荐接口: [直接回车]
✓ 已选择网络接口: end1

✓ 网络接口 'end1' 检查通过
检查系统依赖...
✓ 所有依赖已满足
✓ 检测到已构建的版本
✓ 高性能配置文件已创建
...
启动ARP Spoofer C++ Core...
✓ C++模块加载成功
网络接口: end1
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
