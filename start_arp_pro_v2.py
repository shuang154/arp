#!/usr/bin/env python3
"""
ARP Spoofer Pro V2.0 分级递进式攻击系统启动脚本
========================================================
"""

import os
import sys
import time
import signal
import subprocess
from pathlib import Path

def banner():
    """显示启动横幅"""
    print("=" * 80)
    print("🚀 ARP Spoofer Pro V2.0 - 智能化分级递进式攻击系统")
    print("=" * 80)
    print("升级功能:")
    print("🕵️  智能侦察模式 - 新设备先进行轻量级MiTM观察")
    print("🎯 价值检测升级 - 发现高价值行为时自动升级为全面攻击")
    print("🏆 精准撤退机制 - 捕获凭据后立即恢复目标网络")
    print("⏰ 自动定时管理 - 无价值目标自动释放，避免网络影响")
    print("🧠 智能决策大脑 - Python监督者做出所有策略决策")
    print("⚡ 高效C++执行 - 支持定时攻击和动态升级")
    print("=" * 80)
    print()

def check_dependencies():
    """检查系统依赖"""
    print("🔍 检查系统依赖...")
    
    # 检查权限
    if os.geteuid() != 0:
        print("❌ 错误: 需要root权限运行此程序")
        print("   请使用: sudo python3 start_arp_pro_v2.py")
        return False
    
    # 检查配置文件
    config_file = Path("config/config.yaml")
    if not config_file.exists():
        print(f"❌ 错误: 配置文件不存在: {config_file}")
        return False
    
    # 检查C++可执行文件
    cpp_binary = Path("cpp_core/build/arp_spoofer_core")
    if not cpp_binary.exists():
        print("⚠️  C++核心未编译，尝试自动编译...")
        if not build_cpp_core():
            return False
    
    print("✅ 依赖检查通过")
    return True

def build_cpp_core():
    """编译C++核心"""
    print("🔨 编译C++核心...")
    
    try:
        # 创建build目录
        build_dir = Path("cpp_core/build")
        build_dir.mkdir(exist_ok=True)
        
        # 运行cmake和make
        cmake_cmd = ["cmake", "..", "-DCMAKE_BUILD_TYPE=Release"]
        make_cmd = ["make", "-j4"]
        
        print("   运行cmake...")
        result = subprocess.run(cmake_cmd, cwd=build_dir, 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ CMake失败: {result.stderr}")
            return False
        
        print("   运行make...")
        result = subprocess.run(make_cmd, cwd=build_dir,
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Make失败: {result.stderr}")
            return False
        
        print("✅ C++核心编译成功")
        return True
        
    except Exception as e:
        print(f"❌ 编译失败: {e}")
        return False

def start_cpp_core():
    """启动C++核心"""
    print("🚀 启动C++核心...")
    
    cpp_binary = Path("cpp_core/build/arp_spoofer_core")
    
    # 获取网络接口
    import yaml
    with open("config/config.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    interface = config.get("network", {}).get("interface", "wlan0")
    
    try:
        # 启动C++核心进程
        cpp_process = subprocess.Popen(
            [str(cpp_binary), interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 给C++核心一点时间启动
        time.sleep(2)
        
        # 检查进程是否正常运行
        if cpp_process.poll() is not None:
            stdout, stderr = cpp_process.communicate()
            print(f"❌ C++核心启动失败:")
            print(f"stdout: {stdout}")
            print(f"stderr: {stderr}")
            return None
        
        print(f"✅ C++核心已启动 (PID: {cpp_process.pid})")
        return cpp_process
        
    except Exception as e:
        print(f"❌ 启动C++核心失败: {e}")
        return None

def start_python_supervisor():
    """启动Python监督者"""
    print("🧠 启动Python智能监督者...")
    
    try:
        # 启动Python监督者进程
        python_process = subprocess.Popen(
            [sys.executable, "python_supervisor/main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(1)
        
        if python_process.poll() is not None:
            stdout, stderr = python_process.communicate()
            print(f"❌ Python监督者启动失败:")
            print(f"stdout: {stdout}")
            print(f"stderr: {stderr}")
            return None
        
        print(f"✅ Python监督者已启动 (PID: {python_process.pid})")
        return python_process
        
    except Exception as e:
        print(f"❌ 启动Python监督者失败: {e}")
        return None

def monitor_system(cpp_process, python_process):
    """监控系统运行状态"""
    print("\n🎯 系统启动完成！开始智能侦察...")
    print("=" * 80)
    print("📊 实时状态:")
    print("   - 侦察模式: 活跃 (60秒窗口)")
    print("   - 高价值端口监控: [801, 443]")
    print("   - 目标服务器: 121.248.150.37")
    print("   - 自动定时管理: 启用")
    print()
    print("💡 工作原理:")
    print("   1. 🔍 检测到新设备 → 启动60秒侦察MiTM")
    print("   2. 👁️  监控流量，寻找高价值行为")
    print("   3. 🎯 发现高价值事件 → 升级为全面攻击(60秒)")
    print("   4. 🏆 捕获凭据 → 立即恢复网络并退出")
    print("   5. ⏰ 超时无价值 → 自动恢复网络")
    print()
    print("按 Ctrl+C 优雅停止系统")
    print("=" * 80)
    
    try:
        while True:
            # 检查进程状态
            if cpp_process.poll() is not None:
                print("\n❌ C++核心进程异常退出")
                break
            
            if python_process.poll() is not None:
                print("\n❌ Python监督者进程异常退出")
                break
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 接收到停止信号，正在优雅关闭系统...")
        
        # 发送停止信号
        print("   停止Python监督者...")
        python_process.terminate()
        
        print("   停止C++核心...")
        cpp_process.terminate()
        
        # 等待进程退出
        try:
            python_process.wait(timeout=5)
            cpp_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("   强制终止进程...")
            python_process.kill()
            cpp_process.kill()
        
        print("✅ 系统已安全关闭")

def main():
    """主函数"""
    banner()
    
    # 检查依赖
    if not check_dependencies():
        return 1
    
    # 启动C++核心
    cpp_process = start_cpp_core()
    if not cpp_process:
        return 1
    
    # 启动Python监督者
    python_process = start_python_supervisor()
    if not python_process:
        cpp_process.terminate()
        return 1
    
    # 监控系统
    try:
        monitor_system(cpp_process, python_process)
    except Exception as e:
        print(f"❌ 系统运行错误: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
