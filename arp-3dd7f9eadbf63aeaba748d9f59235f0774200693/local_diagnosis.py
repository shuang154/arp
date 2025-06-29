#!/usr/bin/env python3
"""
本地状态检查工具 - 直接在香橙派上运行，诊断ARP欺骗系统问题
"""
import os
import sys
import subprocess
import time
import signal
import json
from datetime import datetime

def check_process_status():
    """检查进程状态"""
    print("=" * 50)
    print("🔍 进程状态检查")
    print("=" * 50)
    
    # 检查Python进程
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        python_processes = []
        for line in result.stdout.split('\n'):
            if 'python' in line.lower() and ('arp' in line.lower() or 'main.py' in line):
                python_processes.append(line.strip())
        
        if python_processes:
            print("✅ 发现ARP相关Python进程:")
            for i, proc in enumerate(python_processes, 1):
                print(f"  {i}. {proc}")
        else:
            print("❌ 未发现ARP相关Python进程")
    except Exception as e:
        print(f"❌ 检查进程失败: {e}")
    
    # 检查C++进程
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        cpp_processes = []
        for line in result.stdout.split('\n'):
            if 'arp_spoofer' in line or 'cpp_core' in line:
                cpp_processes.append(line.strip())
        
        if cpp_processes:
            print("\n✅ 发现C++核心进程:")
            for i, proc in enumerate(cpp_processes, 1):
                print(f"  {i}. {proc}")
        else:
            print("\n❌ 未发现C++核心进程")
    except Exception as e:
        print(f"❌ 检查C++进程失败: {e}")

def check_network_interface():
    """检查网络接口"""
    print("\n" + "=" * 50)
    print("🌐 网络接口检查")
    print("=" * 50)
    
    try:
        # 显示网络接口
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        interfaces = []
        current_interface = None
        
        for line in result.stdout.split('\n'):
            if ': ' in line and ('eth' in line or 'wlan' in line or 'en' in line):
                current_interface = line.split(':')[1].strip().split('@')[0]
                interfaces.append(current_interface)
        
        print("📡 可用网络接口:")
        for iface in interfaces:
            print(f"  - {iface}")
            
        # 检查默认路由
        result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
        if result.stdout:
            print(f"\n🛣️ 默认路由: {result.stdout.strip()}")
        
    except Exception as e:
        print(f"❌ 检查网络接口失败: {e}")

def check_ports():
    """检查端口占用"""
    print("\n" + "=" * 50)
    print("🔌 端口占用检查")
    print("=" * 50)
    
    ports_to_check = [8080, 8000, 5000, 3000]
    
    for port in ports_to_check:
        try:
            result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
            if f':{port}' in result.stdout:
                # 找到占用该端口的进程
                for line in result.stdout.split('\n'):
                    if f':{port}' in line:
                        print(f"✅ 端口 {port}: {line.strip()}")
                        break
            else:
                print(f"❌ 端口 {port}: 未被占用")
        except Exception as e:
            print(f"❌ 检查端口 {port} 失败: {e}")

def check_log_files():
    """检查日志文件"""
    print("\n" + "=" * 50)
    print("📝 日志文件检查")
    print("=" * 50)
    
    log_paths = [
        "/home/zs/文档/projects/arp_pro/python_supervisor.log",
        "/home/zs/文档/projects/arp_pro/cpp_core.log",
        "./python_supervisor.log",
        "./cpp_core.log",
        "/tmp/arp_spoofer.log"
    ]
    
    for log_path in log_paths:
        if os.path.exists(log_path):
            try:
                stat = os.stat(log_path)
                size = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime)
                print(f"✅ {log_path}")
                print(f"   大小: {size} 字节")
                print(f"   修改时间: {mtime}")
                
                # 显示最后几行
                try:
                    result = subprocess.run(['tail', '-5', log_path], capture_output=True, text=True)
                    if result.stdout:
                        print("   最后5行:")
                        for line in result.stdout.strip().split('\n'):
                            print(f"     {line}")
                except:
                    pass
                print()
            except Exception as e:
                print(f"❌ 读取 {log_path} 失败: {e}")
        else:
            print(f"❌ {log_path}: 文件不存在")

def check_system_resources():
    """检查系统资源"""
    print("\n" + "=" * 50)
    print("💻 系统资源检查")
    print("=" * 50)
    
    try:
        # CPU使用率
        result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'Cpu' in line or '%Cpu' in line:
                print(f"🔥 {line.strip()}")
                break
        
        # 内存使用
        result = subprocess.run(['free', '-h'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            print(f"🧠 内存: {lines[1]}")
        
        # 磁盘空间
        result = subprocess.run(['df', '-h', '.'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            print(f"💾 磁盘: {lines[1]}")
            
    except Exception as e:
        print(f"❌ 检查系统资源失败: {e}")

def check_config_files():
    """检查配置文件"""
    print("\n" + "=" * 50)
    print("⚙️ 配置文件检查")
    print("=" * 50)
    
    config_paths = [
        "/home/zs/文档/projects/arp_pro/config/config.yaml",
        "./config/config.yaml",
        "./config.yaml"
    ]
    
    for config_path in config_paths:
        if os.path.exists(config_path):
            print(f"✅ 配置文件: {config_path}")
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')[:10]  # 显示前10行
                    for line in lines:
                        if line.strip():
                            print(f"   {line}")
                    if len(content.split('\n')) > 10:
                        print("   ...")
            except Exception as e:
                print(f"   ❌ 读取失败: {e}")
        else:
            print(f"❌ 配置文件不存在: {config_path}")

def check_temporary_file():
    """检查临时文件"""
    print("\n" + "=" * 50)
    print("📄 临时文件检查")
    print("=" * 50)
    
    temp_paths = [
        "./temporary.txt",
        "/home/zs/文档/projects/arp_pro/temporary.txt",
        "../arp信息加工/temporary.txt"
    ]
    
    for temp_path in temp_paths:
        if os.path.exists(temp_path):
            try:
                stat = os.stat(temp_path)
                size = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime)
                print(f"✅ {temp_path}")
                print(f"   大小: {size} 字节")
                print(f"   修改时间: {mtime}")
                
                # 显示最后几行
                if size > 0:
                    result = subprocess.run(['tail', '-3', temp_path], capture_output=True, text=True)
                    if result.stdout:
                        print("   最新捕获:")
                        for line in result.stdout.strip().split('\n'):
                            print(f"     {line}")
                else:
                    print("   文件为空")
            except Exception as e:
                print(f"❌ 检查 {temp_path} 失败: {e}")
        else:
            print(f"❌ {temp_path}: 文件不存在")

def quick_diagnosis():
    """快速诊断"""
    print("\n" + "=" * 50)
    print("🔧 快速诊断")
    print("=" * 50)
    
    issues = []
    
    # 检查是否有Python进程
    try:
        result = subprocess.run(['pgrep', '-f', 'python.*arp'], capture_output=True, text=True)
        if not result.stdout.strip():
            issues.append("❌ 没有运行ARP相关的Python进程")
    except:
        pass
    
    # 检查8080端口
    try:
        result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
        if ':8080' not in result.stdout:
            issues.append("❌ 8080端口未被占用 (Web API可能未启动)")
    except:
        pass
    
    # 检查网络接口
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if 'state UP' not in result.stdout:
            issues.append("⚠️ 可能没有活跃的网络接口")
    except:
        pass
    
    if issues:
        print("发现的问题:")
        for issue in issues:
            print(f"  {issue}")
    else:
        print("✅ 未发现明显问题")

def main():
    print("🔍 ARP欺骗系统本地诊断工具")
    print(f"⏰ 检查时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📂 当前目录: {os.getcwd()}")
    print(f"👤 运行用户: {os.getenv('USER', 'unknown')}")
    
    # 执行各项检查
    check_process_status()
    check_network_interface()
    check_ports()
    check_log_files()
    check_config_files()
    check_temporary_file()
    check_system_resources()
    quick_diagnosis()
    
    print("\n" + "=" * 50)
    print("✅ 诊断完成")
    print("=" * 50)
    print("\n💡 建议的排查步骤:")
    print("1. 如果没有Python进程，尝试重新启动: python3 main.py")
    print("2. 如果8080端口未占用，检查Web API配置")
    print("3. 查看日志文件了解详细错误信息")
    print("4. 确认网络接口配置正确")

if __name__ == "__main__":
    main()
