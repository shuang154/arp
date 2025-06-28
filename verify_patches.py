#!/usr/bin/env python3
"""
三大补丁验证脚本
================
验证以下关键修复是否已正确应用：
1. 配置文件中 heartbeat_hwm 已提升到 256
2. C++ 端心跳发送改为 dontwait 非阻塞模式
3. Python 端主业务使用线程池但有进程池支持，避免 GIL 饥饿
4. Python 端统计访问使用安全方法，避免 KeyError
"""

import os
import re
import yaml

def check_config_hwm():
    """检查配置文件中的 HWM 设置"""
    print("🔍 检查补丁1: 配置文件 HWM 设置...")
    config_path = "config/config.yaml"
    
    if not os.path.exists(config_path):
        print("❌ 配置文件不存在")
        return False
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    hwm = config.get('ipc', {}).get('heartbeat_hwm', 0)
    if hwm >= 256:
        print(f"✅ heartbeat_hwm = {hwm} (≥ 256)")
        return True
    else:
        print(f"❌ heartbeat_hwm = {hwm} (< 256)")
        return False

def check_cpp_dontwait():
    """检查 C++ 端是否使用 dontwait 发送"""
    print("\n🔍 检查补丁2: C++ 心跳非阻塞发送...")
    cpp_path = "cpp_core/src/ipc_manager.cpp"
    
    if not os.path.exists(cpp_path):
        print("❌ C++ 文件不存在")
        return False
    
    with open(cpp_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 检查是否使用 dontwait
    if "zmq::send_flags::dontwait" in content:
        print("✅ 发现 dontwait 非阻塞发送")
        
        # 检查是否有丢包统计
        if "ping_drops" in content or "ping_errors" in content:
            print("✅ 发现丢包统计逻辑")
            return True
        else:
            print("⚠️  缺少丢包统计")
            return False
    else:
        print("❌ 未发现 dontwait 发送")
        return False

def check_python_concurrency():
    """检查 Python 端并发处理"""
    print("\n🔍 检查补丁3: Python 并发优化...")
    py_path = "python_supervisor/main.py"
    
    if not os.path.exists(py_path):
        print("❌ Python 文件不存在")
        return False
    
    with open(py_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = {
        "ThreadPoolExecutor": "ThreadPoolExecutor" in content,
        "ProcessPoolExecutor": "ProcessPoolExecutor" in content,
        "安全统计方法": "_safe_stats_increment" in content,
        "安全锁保护": "_safe_stats_get" in content
    }
    
    all_passed = True
    for check_name, passed in checks.items():
        if passed:
            print(f"✅ {check_name}")
        else:
            print(f"❌ {check_name}")
            all_passed = False
    
    return all_passed

def check_attack_coordinator_safety():
    """检查 AttackCoordinator 的安全性"""
    print("\n🔍 检查补丁4: AttackCoordinator 线程安全...")
    ac_path = "python_supervisor/attack_coordinator.py"
    
    if not os.path.exists(ac_path):
        print("❌ AttackCoordinator 文件不存在")
        return False
    
    with open(ac_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if "_safe_stats_increment" in content:
        print("✅ 发现安全统计方法")
        return True
    else:
        print("❌ 缺少安全统计方法")
        return False

def main():
    """主验证函数"""
    print("🚀 ARP 欺骗项目三大补丁验证")
    print("=" * 50)
    
    results = []
    results.append(check_config_hwm())
    results.append(check_cpp_dontwait())
    results.append(check_python_concurrency())
    results.append(check_attack_coordinator_safety())
    
    print("\n" + "=" * 50)
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"🎉 所有补丁验证通过! ({passed}/{total})")
        print("\n✨ 预期效果:")
        print("- C++ 心跳线程不再阻塞 (HWM=256 + dontwait)")
        print("- Python GIL 饥饿大幅减少 (混合线程/进程池)")
        print("- 多线程 KeyError 消失 (安全统计访问)")
        print("- 16秒掉线问题应该彻底解决!")
    else:
        print(f"⚠️  {total-passed} 个补丁需要修复! ({passed}/{total})")
        print("\n建议：")
        print("- 检查配置文件是否正确保存")
        print("- 确认 C++ 代码编译并生效")
        print("- 验证 Python 代码语法无误")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
